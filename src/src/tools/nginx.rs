use serde_json::Value;
use std::fs;
use std::path::{Path, PathBuf};

#[derive(Debug, Clone)]
struct NginxFinding {
    file: String,
    line: Option<usize>,
    severity: &'static str,
    category: &'static str,
    issue: String,
    impact: &'static str,
    remediation: &'static str,
}

pub async fn run(args: Value) -> Result<String, String> {
    let path_str = args
        .get("path")
        .and_then(|v| v.as_str())
        .ok_or_else(|| "Missing required parameter 'path'".to_string())?
        .trim();

    let target_path = Path::new(path_str);
    if !target_path.exists() {
        return Err(format!(
            "Target path '{}' does not exist or is inaccessible",
            path_str
        ));
    }

    let files_to_audit = discover_nginx_files(target_path)?;
    if files_to_audit.is_empty() {
        return Err(format!(
            "No Nginx configuration files (.conf or standard config) detected in path '{}'",
            path_str
        ));
    }

    let mut findings = Vec::new();
    for file in &files_to_audit {
        audit_nginx_file(file, &mut findings)?;
    }

    Ok(format_report(path_str, &files_to_audit, &findings))
}

fn discover_nginx_files(path: &Path) -> Result<Vec<PathBuf>, String> {
    let mut files = Vec::new();
    if path.is_file() {
        files.push(path.to_path_buf());
        return Ok(files);
    }

    if path.is_dir() {
        let entries = fs::read_dir(path)
            .map_err(|e| format!("Failed to read directory '{}': {}", path.display(), e))?;

        for entry in entries.flatten() {
            let entry_path = entry.path();
            if entry_path.is_file() {
                let file_name = entry_path
                    .file_name()
                    .and_then(|n| n.to_str())
                    .unwrap_or("");
                let lower = file_name.to_lowercase();

                if lower.ends_with(".conf")
                    || lower == "nginx.conf"
                    || lower.contains("sites-available")
                    || lower.contains("sites-enabled")
                    || lower == "default"
                {
                    files.push(entry_path);
                }
            } else if entry_path.is_dir() {
                // Recursively check 1 level deep (e.g. conf.d, sites-available)
                if let Ok(sub_entries) = fs::read_dir(&entry_path) {
                    for sub in sub_entries.flatten() {
                        let sub_p = sub.path();
                        if sub_p.is_file() {
                            let name = sub_p.file_name().and_then(|n| n.to_str()).unwrap_or("");
                            if name.ends_with(".conf") || name == "default" {
                                files.push(sub_p);
                            }
                        }
                    }
                }
            }
        }
    }

    Ok(files)
}

fn audit_nginx_file(path: &Path, findings: &mut Vec<NginxFinding>) -> Result<(), String> {
    let content = fs::read_to_string(path)
        .map_err(|e| format!("Failed to read file '{}': {}", path.display(), e))?;

    let file_str = path.display().to_string();
    let lines: Vec<&str> = content.lines().collect();

    let mut current_location: Option<(usize, String)> = None;
    let mut location_has_alias = false;
    let mut location_has_proxy = false;
    let mut location_has_limit_except = false;
    let mut location_has_security_headers = false;
    let mut server_tokens_configured = false;
    let mut brace_depth: i32 = 0;
    let mut location_depth: i32 = 0;

    for (idx, line) in lines.iter().enumerate() {
        let line_num = idx + 1;
        let trimmed = line.trim();

        if trimmed.starts_with('#') || trimmed.is_empty() {
            continue;
        }

        // Track braces to know when we enter/exit a location block
        let open_braces = trimmed.chars().filter(|&c| c == '{').count() as i32;
        let close_braces = trimmed.chars().filter(|&c| c == '}').count() as i32;
        brace_depth += open_braces - close_braces;

        // Detect location block start
        if trimmed.starts_with("location ")
            || trimmed.starts_with("location~")
            || trimmed.starts_with("location^~")
        {
            let parts: Vec<&str> = trimmed.split_whitespace().collect();
            // find location path
            let loc_path = parts.iter().find(|&&p| {
                p.starts_with('/') || p.starts_with('~') || p.starts_with('=') || p.starts_with('@')
            });
            let loc_str = loc_path
                .unwrap_or(&"/")
                .trim_matches('{')
                .trim()
                .to_string();

            current_location = Some((line_num, loc_str));
            location_has_alias = false;
            location_has_proxy = false;
            location_has_limit_except = false;
            location_has_security_headers = false;
            location_depth = brace_depth;
        }

        // Check 1: Off-by-Slash in 'alias' directive
        if let Some(stripped) = trimmed.strip_prefix("alias ") {
            location_has_alias = true;
            let alias_val = stripped.trim().trim_end_matches(';').trim();

            if let Some((_loc_line, ref loc_path)) = current_location {
                let loc_clean = loc_path
                    .trim_start_matches('~')
                    .trim_start_matches('^')
                    .trim_start_matches('=')
                    .trim();
                let loc_ends_slash = loc_clean.ends_with('/');
                let alias_ends_slash = alias_val.ends_with('/');

                if !loc_ends_slash && alias_ends_slash {
                    findings.push(NginxFinding {
                        file: file_str.clone(),
                        line: Some(line_num),
                        severity: "CRITICAL",
                        category: "Path Traversal",
                        issue: format!(
                            "Off-by-Slash directory traversal in alias directive ('location {}' vs 'alias {}')",
                            loc_clean, alias_val
                        ),
                        impact: "An attacker requesting '/path../secret' traverses out of the intended directory into parent folders.",
                        remediation: "Add trailing slash to location directive to match alias (e.g. 'location /path/ { alias /dir/; }').",
                    });
                } else if loc_ends_slash && !alias_ends_slash {
                    findings.push(NginxFinding {
                        file: file_str.clone(),
                        line: Some(line_num),
                        severity: "HIGH",
                        category: "Path Traversal",
                        issue: format!(
                            "Mismatched trailing slash in alias directive ('location {}' vs 'alias {}')",
                            loc_clean, alias_val
                        ),
                        impact: "Can cause unexpected URI resolution or file disclosure depending on Nginx version.",
                        remediation: "Ensure both location and alias directives have matching trailing slash formatting.",
                    });
                }
            }
        }

        // Check 2: Buffer Overflow & Unlimited Body Size
        if let Some(stripped) = trimmed.strip_prefix("client_max_body_size ") {
            let val = stripped.trim().trim_end_matches(';').trim();
            if val == "0" {
                findings.push(NginxFinding {
                    file: file_str.clone(),
                    line: Some(line_num),
                    severity: "HIGH",
                    category: "DoS Defense",
                    issue: "'client_max_body_size 0;' disables request payload limit".to_string(),
                    impact: "Enables Denial of Service attacks by streaming arbitrary large file uploads to fill server disk or memory.",
                    remediation: "Set an explicit reasonable limit (e.g. 'client_max_body_size 10M;').",
                });
            }
        }

        // Check 3: WebDAV methods without restriction
        if let Some(stripped) = trimmed.strip_prefix("dav_methods ") {
            let methods = stripped.trim().trim_end_matches(';').trim();
            if methods.contains("PUT") || methods.contains("DELETE") || methods.contains("MKCOL") {
                findings.push(NginxFinding {
                    file: file_str.clone(),
                    line: Some(line_num),
                    severity: "HIGH",
                    category: "Insecure HTTP Methods",
                    issue: format!("Destructive WebDAV methods enabled ('dav_methods {}')", methods),
                    impact: "Allows arbitrary file upload, modification, or deletion on server without external authentication controls.",
                    remediation: "Disable WebDAV or enforce strict client IP whitelisting and mutual TLS / basic authentication.",
                });
            }
        }

        // Check 4: Directory Listing (autoindex on)
        if trimmed.contains("autoindex on;") {
            findings.push(NginxFinding {
                file: file_str.clone(),
                line: Some(line_num),
                severity: "HIGH",
                category: "Information Leakage",
                issue: "Directory listing is enabled ('autoindex on;')".to_string(),
                impact: "Exposes directory structure and confidential files to unauthenticated public visitors.",
                remediation: "Disable directory indexing by setting 'autoindex off;'.",
            });
        }

        // Check 5: Server Tokens (server_tokens on / off)
        if trimmed.contains("server_tokens on;") {
            findings.push(NginxFinding {
                file: file_str.clone(),
                line: Some(line_num),
                severity: "LOW",
                category: "Information Leakage",
                issue: "Server version banner disclosure enabled ('server_tokens on;')".to_string(),
                impact: "Reveals exact Nginx version in HTTP response Server header and default error pages.",
                remediation: "Disable version disclosure by adding 'server_tokens off;'.",
            });
            server_tokens_configured = true;
        } else if trimmed.contains("server_tokens off;") {
            server_tokens_configured = true;
        }

        // Check 6: Insecure SSL/TLS Protocols & Ciphers
        if let Some(stripped) = trimmed.strip_prefix("ssl_protocols ") {
            let protos = stripped.trim().trim_end_matches(';').trim();
            if protos.contains("TLSv1.0")
                || protos.contains("TLSv1.1")
                || protos.contains("TLSv1 ")
                || protos.ends_with("TLSv1")
                || protos.contains("SSLv3")
            {
                findings.push(NginxFinding {
                    file: file_str.clone(),
                    line: Some(line_num),
                    severity: "HIGH",
                    category: "TLS Cryptography",
                    issue: format!("Obsolete and vulnerable SSL/TLS protocols configured ('{}')", protos),
                    impact: "Exposes TLS sessions to POODLE, BEAST, and Sweet32 cryptographic downgrade attacks.",
                    remediation: "Enforce TLS 1.2 and TLS 1.3 only: 'ssl_protocols TLSv1.2 TLSv1.3;'.",
                });
            }
        }

        if let Some(stripped) = trimmed.strip_prefix("ssl_ciphers ") {
            let ciphers = stripped.trim().trim_end_matches(';').trim();
            if ciphers.contains("RC4")
                || ciphers.contains("MD5")
                || ciphers.contains("DES")
                || ciphers.contains("EXPORT")
            {
                findings.push(NginxFinding {
                    file: file_str.clone(),
                    line: Some(line_num),
                    severity: "HIGH",
                    category: "TLS Cryptography",
                    issue: format!("Insecure or broken cipher suites enabled in 'ssl_ciphers' ('{}')", ciphers),
                    impact: "Weak ciphers are susceptible to offline brute-force or passive plaintext reconstruction.",
                    remediation: "Use modern secure AEAD cipher suites (e.g. 'ECDHE-ECDSA-AES128-GCM-SHA256:ECDHE-RSA-AES128-GCM-SHA256').",
                });
            }
        }

        // Check 7: URI Slash Merging (merge_slashes off)
        if trimmed.contains("merge_slashes off;") {
            findings.push(NginxFinding {
                file: file_str.clone(),
                line: Some(line_num),
                severity: "MEDIUM",
                category: "Access Control Bypass",
                issue: "URI slash merging is disabled ('merge_slashes off;')".to_string(),
                impact: "Allows attackers to bypass path-based access control rules using multiple consecutive slashes (e.g. '///admin').",
                remediation: "Remove directive or set 'merge_slashes on;' to normalize request URIs.",
            });
        }

        // Check 8: Insecure CORS Wildcard with Credentials
        if trimmed.contains("add_header")
            && trimmed.contains("Access-Control-Allow-Origin")
            && trimmed.contains('*')
        {
            findings.push(NginxFinding {
                file: file_str.clone(),
                line: Some(line_num),
                severity: "MEDIUM",
                category: "CORS Misconfiguration",
                issue: "Wildcard origin specified in Access-Control-Allow-Origin header ('*')".to_string(),
                impact: "Allows any arbitrary origin to query public API responses.",
                remediation: "If sensitive data or credentials are required, validate and reflect only explicitly whitelisted origins.",
            });
        }

        // Track proxy_pass, limit_except, and security headers
        if trimmed.starts_with("proxy_pass ") {
            location_has_proxy = true;
        }
        if trimmed.starts_with("limit_except ") {
            location_has_limit_except = true;
        }
        if trimmed.starts_with("add_header ")
            && (trimmed.contains("X-Frame-Options")
                || trimmed.contains("X-Content-Type-Options")
                || trimmed.contains("Content-Security-Policy"))
        {
            location_has_security_headers = true;
        }

        // Check when exiting location block
        if current_location.is_some() && brace_depth < location_depth {
            if let Some((loc_line, ref loc_path)) = current_location {
                // Check if sensitive endpoint lacks limit_except
                let lower_loc = loc_path.to_lowercase();
                if (lower_loc.contains("/admin")
                    || lower_loc.contains("/api")
                    || lower_loc.contains("/upload"))
                    && !location_has_limit_except
                    && !location_has_alias
                {
                    findings.push(NginxFinding {
                        file: file_str.clone(),
                        line: Some(loc_line),
                        severity: "MEDIUM",
                        category: "HTTP Method Enforcement",
                        issue: format!("Sensitive location '{}' lacks 'limit_except' method restrictions", loc_path),
                        impact: "Unrestricted HTTP methods (such as DELETE, PUT, TRACE) may be accepted by upstream handlers.",
                        remediation: "Add 'limit_except GET POST HEAD { deny all; }' inside the location block.",
                    });
                }

                // Check if reverse proxy location lacks security defense headers
                if location_has_proxy && !location_has_security_headers {
                    findings.push(NginxFinding {
                        file: file_str.clone(),
                        line: Some(loc_line),
                        severity: "LOW",
                        category: "Defense Headers",
                        issue: format!("Reverse proxy location '{}' missing basic defense headers in proxy block", loc_path),
                        impact: "Downstream browsers miss clickjacking (X-Frame-Options) and MIME-confusion (X-Content-Type-Options) protections.",
                        remediation: "Add 'add_header X-Frame-Options SAMEORIGIN always;' and 'add_header X-Content-Type-Options nosniff always;'.",
                    });
                }
            }

            current_location = None;
        }
    }

    if !server_tokens_configured && content.contains("http {") {
        findings.push(NginxFinding {
            file: file_str,
            line: None,
            severity: "LOW",
            category: "Information Leakage",
            issue: "No 'server_tokens off;' directive found in configuration".to_string(),
            impact: "Default Nginx error pages and response headers will broadcast the exact Nginx server version.",
            remediation: "Add 'server_tokens off;' to the http context.",
        });
    }

    Ok(())
}

fn format_report(target: &str, files: &[PathBuf], findings: &[NginxFinding]) -> String {
    let mut report = String::new();
    report.push_str("# SecLens Infrastructure Security: Nginx Configuration Lint & Audit\n\n");
    report.push_str(&format!("- **Target Path:** `{}`\n", target));
    report.push_str(&format!(
        "- **Audited Configuration Files:** {}\n",
        files.len()
    ));
    for f in files {
        report.push_str(&format!("  * `{}`\n", f.display()));
    }
    report.push('\n');

    let crit_count = findings.iter().filter(|f| f.severity == "CRITICAL").count();
    let high_count = findings.iter().filter(|f| f.severity == "HIGH").count();
    let med_count = findings.iter().filter(|f| f.severity == "MEDIUM").count();
    let low_count = findings.iter().filter(|f| f.severity == "LOW").count();
    let total = findings.len();

    let (score, grade) = calculate_nginx_score(crit_count, high_count, med_count, low_count);

    report.push_str(&format!(
        "### Configuration Hardening Score: **{} / 100** (Grade: **{}**)\n\n",
        score, grade
    ));

    report.push_str("| Risk Metric | Occurrences |\n");
    report.push_str("| :--- | :---: |\n");
    report.push_str(&format!(
        "| **Critical Vulnerabilities** | `{}` |\n",
        crit_count
    ));
    report.push_str(&format!(
        "| **High Severity Issues** | `{}` |\n",
        high_count
    ));
    report.push_str(&format!(
        "| **Medium Severity Issues** | `{}` |\n",
        med_count
    ));
    report.push_str(&format!(
        "| **Low / Informational Findings** | `{}` |\n",
        low_count
    ));
    report.push_str(&format!(
        "| **Total Identified Issues** | `{}` |\n\n",
        total
    ));

    if findings.is_empty() {
        report.push_str("> **PASS: Clean Nginx configuration.** No Off-by-Slash directory traversals, buffer overflows, insecure WebDAV methods, or obsolete TLS ciphers were detected.\n");
        return report;
    }

    report.push_str("### Detailed Configuration Findings Matrix\n\n");
    report.push_str("| File | Line | Severity | Category | Configuration Issue | Impact | Remediation Advice |\n");
    report.push_str("| :--- | :---: | :---: | :--- | :--- | :--- | :--- |\n");

    for f in findings {
        let line_str = match f.line {
            Some(l) => l.to_string(),
            None => "-".to_string(),
        };

        let sev_badge = match f.severity {
            "CRITICAL" => "**CRITICAL**",
            "HIGH" => "**HIGH**",
            "MEDIUM" => "MEDIUM",
            _ => "LOW",
        };

        report.push_str(&format!(
            "| `{}` | {} | {} | {} | {} | {} | {} |\n",
            f.file, line_str, sev_badge, f.category, f.issue, f.impact, f.remediation
        ));
    }

    report.push_str("\n### Actionable Remediation Roadmap\n");
    if crit_count > 0 {
        report.push_str("- [P0] **OFF-BY-SLASH TRAVERSAL:** Immediately align trailing slashes between `location` and `alias` directives to prevent arbitrary filesystem leakage.\n");
    }
    if high_count > 0 {
        report.push_str("- [P1] **HIGH RISKS:** Disable `client_max_body_size 0`, eliminate unauthenticated `dav_methods`, disable `autoindex on`, and restrict `ssl_protocols` to TLS 1.2+.\n");
    }
    if med_count > 0 {
        report.push_str("- [P2] **ACCESS & HEADERS:** Restrict HTTP methods with `limit_except` on sensitive endpoints and inject missing security headers in reverse proxy blocks.\n");
    }

    report
}

fn calculate_nginx_score(crit: usize, high: usize, med: usize, low: usize) -> (u32, &'static str) {
    let mut deduction = 0;
    deduction += crit * 35;
    deduction += high * 20;
    deduction += med * 10;
    deduction += low * 4;

    let score = if deduction >= 100 {
        0
    } else {
        100 - deduction as u32
    };
    let grade = match score {
        95..=100 => "A+",
        85..=94 => "A",
        70..=84 => "B",
        55..=69 => "C",
        40..=54 => "D",
        _ => "F",
    };

    (score, grade)
}
