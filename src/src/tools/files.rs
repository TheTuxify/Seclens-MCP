use crate::engine::Engine;
use serde_json::Value;
use std::sync::Arc;
use std::time::Duration;
use tokio::sync::Semaphore;

const SENSITIVE_PATHS: &[(&str, &str)] = &[
    // Environment & Configuration Files
    (
        ".env",
        "Environment file containing database credentials, API secrets, and encryption keys",
    ),
    (".env.local", "Local development environment credentials"),
    (
        ".env.production",
        "Production environment configuration and credentials",
    ),
    (".env.backup", "Backup copy of sensitive environment file"),
    (
        ".env.example",
        "Template environment file (may leak config schemas)",
    ),
    (
        "config.json",
        "Application configuration file with private connection strings",
    ),
    (
        "config.yml",
        "YAML configuration file possibly containing production keys",
    ),
    (
        "credentials.json",
        "Service account or cloud provider credentials file",
    ),
    (
        "web.config",
        "Microsoft IIS web server configuration and database credentials",
    ),
    (
        ".htaccess",
        "Apache web server directory security and rewrite rules",
    ),
    // Git / VCS Repositories
    (
        ".git/HEAD",
        "Git repository HEAD pointer; allows source-code extraction",
    ),
    (
        ".git/config",
        "Git repository config; may contain hardcoded auth tokens or private URLs",
    ),
    (
        ".git/index",
        "Git staging index file; exposes complete project tree structure",
    ),
    // Container & Orchestration
    (
        "docker-compose.yml",
        "Docker infrastructure definition and container secret mappings",
    ),
    ("docker-compose.yaml", "Alternative Docker Compose file"),
    (
        "docker-compose.override.yml",
        "Local Docker override file with development secrets",
    ),
    (
        "Dockerfile",
        "Container build instructions revealing internal stack and ports",
    ),
    // Database Dumps & Backups
    (
        "backup.sql",
        "Raw database SQL dump file with plain-text records",
    ),
    ("dump.sql", "Database SQL dump file"),
    ("database.sqlite", "Directly downloadable SQLite database"),
    ("database.sqlite3", "Directly downloadable SQLite3 database"),
    (
        "db.sqlite3",
        "Django / Python standard SQLite database file",
    ),
    // Logs & Framework Storage
    (
        "storage/logs/laravel.log",
        "Laravel application exception log; discloses stack traces & secrets",
    ),
    (
        "storage/oauth-private.key",
        "Laravel Passport / OAuth private RSA signing key",
    ),
    (
        "app.log",
        "Application error log exposing internal API calls",
    ),
    (
        "server-status",
        "Apache server-status internal monitoring dashboard",
    ),
    (
        "phpinfo.php",
        "Complete PHP runtime environment and superglobals disclosure",
    ),
    // Cryptographic Keys
    ("id_rsa", "OpenSSH private cryptographic key"),
    (
        "id_rsa.pub",
        "OpenSSH public key revealing server usernames and hosts",
    ),
    ("id_ed25519", "Ed25519 private cryptographic key"),
    // CMS & Dependency Manifests
    (
        "wp-config.php.bak",
        "WordPress configuration backup file with database credentials",
    ),
    ("wp-config.php.save", "WordPress editor temporary save file"),
    ("wp-config.php.old", "Archived WordPress configuration file"),
    (
        "composer.json",
        "PHP Composer dependencies disclosing vulnerable package versions",
    ),
    (
        "package.json",
        "Node.js dependencies and build scripts disclosure",
    ),
    // Spring Boot Actuators & API Docs
    (
        "actuator/env",
        "Spring Boot Actuator environment endpoint (discloses env vars)",
    ),
    (
        "actuator/health",
        "Spring Boot health status exposing internal service health",
    ),
    (
        "swagger.json",
        "OpenAPI / Swagger endpoint documentation exposing hidden routes",
    ),
    ("openapi.json", "OpenAPI 3.0 specification definition"),
];

struct CalibrationResult {
    is_spa_soft_404: bool,
    #[allow(dead_code)]
    baseline_status: u16,
    baseline_len: usize,
    summary: String,
}

pub async fn run(args: Value, engine: &Engine) -> Result<String, String> {
    let url_str = args
        .get("url")
        .and_then(|v| v.as_str())
        .ok_or_else(|| "Missing required parameter 'url'".to_string())?;

    let base_url = url_str.trim_end_matches('/');
    let base_url = if !base_url.starts_with("http://") && !base_url.starts_with("https://") {
        format!("https://{}", base_url)
    } else {
        base_url.to_string()
    };

    // 1. Soft-404 Calibration Probe
    let calibration = calibrate_soft_404(&base_url, engine).await;

    // 2. Bounded Concurrent Audit (Semaphore: 10, Timeout: 4s)
    let semaphore = Arc::new(Semaphore::new(10));
    let mut tasks = Vec::new();

    let cal_is_spa = calibration.is_spa_soft_404;
    let cal_baseline_len = calibration.baseline_len;

    for (path, desc) in SENSITIVE_PATHS {
        let permit = semaphore
            .clone()
            .acquire_owned()
            .await
            .map_err(|e| e.to_string())?;
        let client = engine.client.clone();
        let target_url = format!("{}/{}", base_url, path);
        let path_str = path.to_string();
        let desc_str = desc.to_string();

        tasks.push(tokio::spawn(async move {
            let _permit = permit;
            let req_future = client.get(&target_url).send();
            let timeout_future = tokio::time::timeout(Duration::from_secs(4), req_future);

            match timeout_future.await {
                Ok(Ok(res)) => {
                    let status = res.status();
                    let content_type = res
                        .headers()
                        .get("content-type")
                        .and_then(|v| v.to_str().ok())
                        .unwrap_or("")
                        .to_string();

                    let body_bytes = res.bytes().await.unwrap_or_default();
                    let body_len = body_bytes.len();

                    let verdict = evaluate_finding(
                        status.as_u16(),
                        &content_type,
                        body_len,
                        cal_is_spa,
                        cal_baseline_len,
                        &path_str,
                    );

                    (path_str, desc_str, status.as_u16(), body_len, verdict)
                }
                Ok(Err(_)) => (path_str, desc_str, 0, 0, FindingVerdict::NetworkError),
                Err(_) => (path_str, desc_str, 0, 0, FindingVerdict::Timeout),
            }
        }));
    }

    let results = futures::future::join_all(tasks).await;

    // 3. Assemble Audit Report
    let mut report = String::new();
    report.push_str("# SecLens Sensitive File Exposure Audit\n");
    report.push_str(&format!("- **Target Base:** `{}`\n", base_url));
    report.push_str(&format!(
        "- **Paths Tested:** `{}`\n",
        SENSITIVE_PATHS.len()
    ));
    report.push_str(&format!(
        "- **Soft-404 Anti-False-Positive Calibration:** {}\n\n",
        calibration.summary
    ));

    report.push_str("| Sensitive Path | HTTP Status | Verdict | Exposure Risk Description |\n");
    report.push_str("| :--- | :---: | :---: | :--- |\n");

    let mut critical_count = 0;
    let mut warning_count = 0;

    for (path, desc, status, body_len, verdict) in results.into_iter().flatten() {
        match verdict {
            FindingVerdict::CriticalLeak => {
                critical_count += 1;
                report.push_str(&format!(
                    "| `/{}` | `{}` ({} bytes) | **CRITICAL LEAK** | {} |\n",
                    path, status, body_len, desc
                ));
            }
            FindingVerdict::ProbableLeak => {
                warning_count += 1;
                report.push_str(&format!(
                    "| `/{}` | `{}` ({} bytes) | **HIGH RISK** | {} (Non-HTML response) |\n",
                    path, status, body_len, desc
                ));
            }
            FindingVerdict::Forbidden => {
                report.push_str(&format!(
                    "| `/{}` | `403` | **FORBIDDEN** | Path exists but access is blocked by server rule. |\n",
                    path
                ));
            }
            FindingVerdict::Soft404 => {
                // Not a leak, SPA or custom 404 handler
            }
            FindingVerdict::NotFound => {
                // Clean 404, omitted from table to keep markdown compact and readable
            }
            FindingVerdict::Timeout => {
                // Timed out probe
            }
            FindingVerdict::NetworkError => {
                // Connection failed probe
            }
        }
    }

    report.push_str("\n### Executive Summary\n");
    if critical_count > 0 {
        report.push_str(&format!(
            "> **CRITICAL ALERT:** Discovered **{}** confirmed sensitive file leaks! Attackers may extract credentials, database dumps or source trees immediately.\n",
            critical_count
        ));
    } else if warning_count > 0 {
        report.push_str(&format!(
            "> **WARNING:** Detected **{}** anomalous endpoints returning data. Further manual inspection recommended.\n",
            warning_count
        ));
    } else {
        report.push_str("> **CLEAN:** No exposed secret files, Git repositories, or environment backups were accessible.\n");
    }

    Ok(report)
}

#[derive(Clone, Copy, PartialEq, Eq)]
enum FindingVerdict {
    CriticalLeak,
    ProbableLeak,
    Forbidden,
    Soft404,
    NotFound,
    Timeout,
    NetworkError,
}

fn evaluate_finding(
    status: u16,
    content_type: &str,
    body_len: usize,
    is_spa_soft_404: bool,
    baseline_len: usize,
    path: &str,
) -> FindingVerdict {
    if status == 403 {
        return FindingVerdict::Forbidden;
    }

    if status == 404 {
        return FindingVerdict::NotFound;
    }

    if status == 200 {
        let is_html = content_type.to_lowercase().contains("text/html");

        // If target host behaves like a Single Page App (returning 200 for missing pages)
        if is_spa_soft_404 {
            let length_diff = body_len.abs_diff(baseline_len);

            // If it returns HTML and body length is close to the 404 probe, it is a false-positive SPA fallback
            if is_html && length_diff < 200 {
                return FindingVerdict::Soft404;
            }
        }

        // Specific signatures for critical hits
        if path.starts_with(".git/") && (body_len > 0 && !is_html) {
            return FindingVerdict::CriticalLeak;
        }

        if (path.ends_with(".env") || path.contains(".env.")) && !is_html && body_len > 0 {
            return FindingVerdict::CriticalLeak;
        }

        if (path.ends_with(".sql") || path.contains("sqlite") || path.ends_with(".key")) && !is_html
        {
            return FindingVerdict::CriticalLeak;
        }

        if !is_html && body_len > 10 {
            return FindingVerdict::ProbableLeak;
        }

        return FindingVerdict::Soft404;
    }

    FindingVerdict::NotFound
}

async fn calibrate_soft_404(base_url: &str, engine: &Engine) -> CalibrationResult {
    let nonce = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_millis())
        .unwrap_or(0);
    let probe_url = format!("{}/_seclens_probe_404_nonce_{:x}", base_url, nonce);

    let probe_resp =
        tokio::time::timeout(Duration::from_secs(4), engine.client.get(&probe_url).send()).await;

    match probe_resp {
        Ok(Ok(res)) => {
            let status = res.status().as_u16();
            let body = res.bytes().await.unwrap_or_default();
            let body_len = body.len();

            if status == 200 {
                CalibrationResult {
                    is_spa_soft_404: true,
                    baseline_status: 200,
                    baseline_len: body_len,
                    summary: format!(
                        "Calibrated (SPA Mode Detected: Non-existent routes return HTTP 200 with ~{} bytes). False positives suppressed.",
                        body_len
                    ),
                }
            } else {
                CalibrationResult {
                    is_spa_soft_404: false,
                    baseline_status: status,
                    baseline_len: body_len,
                    summary: format!(
                        "Calibrated (Standard Behavior: Missing routes correctly return HTTP {}).",
                        status
                    ),
                }
            }
        }
        _ => CalibrationResult {
            is_spa_soft_404: false,
            baseline_status: 0,
            baseline_len: 0,
            summary: "Calibration probe unreachable; proceeding with standard heuristic filtering."
                .to_string(),
        },
    }
}
