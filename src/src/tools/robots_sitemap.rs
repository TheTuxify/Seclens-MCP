use crate::engine::Engine;
use regex::Regex;
use reqwest::Url;
use serde_json::Value;
use std::time::Duration;

#[derive(Debug, Clone)]
struct DisallowFinding {
    path: String,
    user_agent: String,
    severity: &'static str,
    category: &'static str,
    risk_description: &'static str,
}

pub async fn run(args: Value, engine: &Engine) -> Result<String, String> {
    let url_str = args
        .get("url")
        .and_then(|v| v.as_str())
        .ok_or_else(|| "Missing required parameter 'url'".to_string())?
        .trim();

    let target_url =
        Url::parse(url_str).map_err(|e| format!("Invalid URL '{}': {}", url_str, e))?;

    let base_origin = format!(
        "{}://{}",
        target_url.scheme(),
        target_url.host_str().unwrap_or("localhost")
    );

    let robots_url = format!("{}/robots.txt", base_origin);
    let sitemap_url = format!("{}/sitemap.xml", base_origin);

    // Fetch robots.txt and sitemap.xml concurrently
    let (robots_res, sitemap_res) = tokio::join!(
        engine
            .client
            .get(&robots_url)
            .timeout(Duration::from_secs(6))
            .send(),
        engine
            .client
            .get(&sitemap_url)
            .timeout(Duration::from_secs(6))
            .send()
    );

    let robots_body = match robots_res {
        Ok(r) if r.status().is_success() => Some(r.text().await.unwrap_or_default()),
        _ => None,
    };

    let (sitemap_found, sitemap_urls) = match sitemap_res {
        Ok(r) if r.status().is_success() => {
            let body = r.text().await.unwrap_or_default();
            let urls = extract_sitemap_urls(&body);
            (true, urls)
        }
        _ => (false, Vec::new()),
    };

    if robots_body.is_none() && !sitemap_found {
        return Err(format!(
            "Neither robots.txt nor sitemap.xml could be retrieved from '{}'",
            base_origin
        ));
    }

    let (disallow_findings, declared_sitemaps) = if let Some(ref text) = robots_body {
        parse_robots_txt(text)
    } else {
        (Vec::new(), Vec::new())
    };

    Ok(format_report(
        &base_origin,
        robots_body.is_some(),
        &disallow_findings,
        &declared_sitemaps,
        sitemap_found,
        &sitemap_urls,
    ))
}

fn parse_robots_txt(content: &str) -> (Vec<DisallowFinding>, Vec<String>) {
    let mut findings = Vec::new();
    let mut sitemaps = Vec::new();
    let mut current_agent = "*".to_string();

    for line in content.lines() {
        let trimmed = line.trim();
        if trimmed.starts_with('#') || trimmed.is_empty() {
            continue;
        }

        let lower = trimmed.to_lowercase();
        if lower.starts_with("user-agent:") {
            current_agent = trimmed[11..].trim().to_string();
        } else if lower.starts_with("sitemap:") {
            let s_url = trimmed[8..].trim().to_string();
            if !s_url.is_empty() {
                sitemaps.push(s_url);
            }
        } else if lower.starts_with("disallow:") {
            let path = trimmed[9..].trim().to_string();
            if !path.is_empty() && path != "/" {
                let (sev, cat, desc) = classify_disallowed_path(&path);
                findings.push(DisallowFinding {
                    path,
                    user_agent: current_agent.clone(),
                    severity: sev,
                    category: cat,
                    risk_description: desc,
                });
            }
        }
    }

    (findings, sitemaps)
}

fn classify_disallowed_path(path: &str) -> (&'static str, &'static str, &'static str) {
    let lower = path.to_lowercase();

    // 1. Backups & Configs (Critical)
    if lower.contains("backup")
        || lower.contains("dump")
        || lower.contains(".sql")
        || lower.contains(".env")
        || lower.contains("config")
        || lower.contains(".git")
    {
        return (
            "CRITICAL",
            "Sensitive Data Leak",
            "Exposes potential database dumps, configuration backups, or credentials",
        );
    }

    // 2. Admin & Management Consoles (High)
    if lower.contains("admin")
        || lower.contains("administrator")
        || lower.contains("dashboard")
        || lower.contains("control")
        || lower.contains("manage")
        || lower.contains("cpanel")
        || lower.contains("wp-admin")
    {
        return (
            "HIGH",
            "Admin Surface",
            "Directly reveals privileged administrative control panel or portal",
        );
    }

    // 3. Staging & Internal Environments (High)
    if lower.contains("staging")
        || lower.contains("dev")
        || lower.contains("internal")
        || lower.contains("private")
        || lower.contains("secret")
        || lower.contains("test")
    {
        return (
            "HIGH",
            "Internal Surface",
            "Discloses pre-production, staging, or internal microservices",
        );
    }

    // 4. API Endpoints (Medium)
    if lower.contains("/api")
        || lower.contains("/v1")
        || lower.contains("/v2")
        || lower.contains("graphql")
    {
        return (
            "MEDIUM",
            "API Endpoint",
            "Discloses hidden or internal API routes to web crawlers",
        );
    }

    // 5. Auth & Users (Medium)
    if lower.contains("login")
        || lower.contains("auth")
        || lower.contains("account")
        || lower.contains("checkout")
    {
        return (
            "MEDIUM",
            "Authentication",
            "Authentication or user management route listed",
        );
    }

    (
        "LOW",
        "Routine Crawler Block",
        "Standard non-sensitive crawling restriction",
    )
}

fn extract_sitemap_urls(xml_body: &str) -> Vec<String> {
    let loc_re = match Regex::new(r#"(?i)<loc>\s*([^<\s]+)\s*</loc>"#) {
        Ok(r) => r,
        Err(_) => return Vec::new(),
    };

    let mut urls = Vec::new();
    for cap in loc_re.captures_iter(xml_body) {
        let u = cap[1].to_string();
        urls.push(u);
        if urls.len() >= 30 {
            break; // Sample max 30 URLs
        }
    }
    urls
}

fn format_report(
    origin: &str,
    has_robots: bool,
    disallows: &[DisallowFinding],
    sitemaps: &[String],
    has_sitemap: bool,
    sitemap_samples: &[String],
) -> String {
    let mut report = String::new();
    report.push_str("# SecLens Reconnaissance: robots.txt & Sitemap Audit\n\n");
    report.push_str(&format!("- **Target Origin:** `{}`\n", origin));
    report.push_str(&format!(
        "- **robots.txt Status:** {}\n",
        if has_robots {
            "✅ Present"
        } else {
            "❌ Missing / Unreachable"
        }
    ));
    report.push_str(&format!(
        "- **sitemap.xml Status:** {}\n\n",
        if has_sitemap {
            "✅ Present"
        } else {
            "❌ Missing"
        }
    ));

    let crit_count = disallows
        .iter()
        .filter(|d| d.severity == "CRITICAL")
        .count();
    let high_count = disallows.iter().filter(|d| d.severity == "HIGH").count();
    let med_count = disallows.iter().filter(|d| d.severity == "MEDIUM").count();

    report.push_str("### Executive Findings Summary\n\n");
    report.push_str("| Metric | Value |\n");
    report.push_str("| :--- | :---: |\n");
    report.push_str(&format!(
        "| **Critical Leaks in Disallow** | `{}` |\n",
        crit_count
    ));
    report.push_str(&format!(
        "| **High-Risk Admin/Internal Routes** | `{}` |\n",
        high_count
    ));
    report.push_str(&format!("| **API & Auth Disallows** | `{}` |\n", med_count));
    report.push_str(&format!(
        "| **Total Disallow Directives** | `{}` |\n",
        disallows.len()
    ));
    report.push_str(&format!(
        "| **Declared Sitemaps** | `{}` |\n\n",
        sitemaps.len()
    ));

    if crit_count > 0 || high_count > 0 {
        report.push_str("> [!WARNING]\n");
        report.push_str("> **SECURITY THROUGH OBSCURITY HAZARD:**\n");
        report.push_str("> `robots.txt` is publicly readable by any visitor or attacker. Listing secret URLs, admin dashboards, or backup locations in `Disallow:` serves as an explicit reconnaissance roadmap for adversaries.\n\n");
    }

    if !disallows.is_empty() {
        report.push_str("### Disallowed Paths & Exposure Assessment\n\n");
        report
            .push_str("| Disallow Path | User-Agent | Severity | Category | Risk Implication |\n");
        report.push_str("| :--- | :---: | :---: | :--- | :--- |\n");

        for d in disallows {
            let sev_badge = match d.severity {
                "CRITICAL" => "**CRITICAL**",
                "HIGH" => "**HIGH**",
                "MEDIUM" => "MEDIUM",
                _ => "LOW",
            };

            report.push_str(&format!(
                "| `{}` | `{}` | {} | {} | {} |\n",
                d.path, d.user_agent, sev_badge, d.category, d.risk_description
            ));
        }
        report.push('\n');
    }

    if !sitemaps.is_empty() {
        report.push_str("### Sitemaps Declared in robots.txt\n\n");
        for s in sitemaps {
            report.push_str(&format!("- `{}`\n", s));
        }
        report.push('\n');
    }

    if has_sitemap && !sitemap_samples.is_empty() {
        report.push_str(&format!(
            "### Sampled Sitemap URLs (Showing first {} entries)\n\n",
            sitemap_samples.len()
        ));
        for u in sitemap_samples {
            report.push_str(&format!("- `{}`\n", u));
        }
        report.push('\n');
    }

    report.push_str("### Hardening & Defense Recommendations\n");
    report.push_str("1. **Remove Sensitive Endpoints from robots.txt:** Never rely on `Disallow:` to protect confidential portals, internal staging environments, or backup directories.\n");
    report.push_str("2. **Implement Server-Side Access Controls:** Enforce IP whitelisting, mutual TLS, or OAuth2/SSO authentication at the web server / reverse proxy layer rather than relying on crawler compliance.\n");
    report.push_str("3. **Return 404 for Unauthenticated Users:** For sensitive endpoints, consider returning standard 404 Not Found responses to unauthenticated external IP addresses.\n");

    report
}
