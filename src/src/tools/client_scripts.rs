use crate::engine::Engine;
use regex::Regex;
use reqwest::Url;
use serde_json::Value;
use std::time::Duration;

#[derive(Debug, Clone)]
struct ScriptFinding {
    resource_type: &'static str,
    url: String,
    is_external: bool,
    has_sri: bool,
    integrity: Option<String>,
    has_crossorigin: bool,
    vulnerable_lib: Option<(&'static str, &'static str, &'static str)>, // (lib, detected_ver, advisory)
}

pub async fn run(args: Value, engine: &Engine) -> Result<String, String> {
    let url_str = args
        .get("url")
        .and_then(|v| v.as_str())
        .ok_or_else(|| "Missing required parameter 'url'".to_string())?
        .trim();

    let target_url =
        Url::parse(url_str).map_err(|e| format!("Invalid URL '{}': {}", url_str, e))?;

    let base_domain = target_url.host_str().unwrap_or("").to_lowercase();

    let response = engine
        .client
        .get(target_url.clone())
        .timeout(Duration::from_secs(8))
        .send()
        .await
        .map_err(|e| format!("Failed to connect to '{}': {}", url_str, e))?;

    let status = response.status();
    if !status.is_success() {
        return Err(format!(
            "Target returned non-success HTTP status {} ({})",
            status.as_u16(),
            status
        ));
    }

    let html_body = response
        .text()
        .await
        .map_err(|e| format!("Failed to read response body: {}", e))?;

    let findings = extract_and_audit_resources(&html_body, &target_url, &base_domain)?;

    Ok(format_report(url_str, &findings))
}

fn extract_and_audit_resources(
    html: &str,
    base_url: &Url,
    base_domain: &str,
) -> Result<Vec<ScriptFinding>, String> {
    let mut findings = Vec::new();

    // Regex for <script ...> tags
    let script_regex = Regex::new(r#"(?i)<script\b([^>]*)>(.*?)</script>|<script\b([^>]*)/>"#)
        .map_err(|e| format!("Regex error: {}", e))?;
    let link_regex =
        Regex::new(r#"(?i)<link\b([^>]*)>"#).map_err(|e| format!("Regex error: {}", e))?;
    let attr_regex = Regex::new(r#"(?i)([a-z0-9_-]+)\s*=\s*["']([^"']*)["']"#)
        .map_err(|e| format!("Regex error: {}", e))?;

    // 1. Audit Scripts
    for cap in script_regex.captures_iter(html) {
        let attrs_str = cap.get(1).or_else(|| cap.get(3)).map_or("", |m| m.as_str());

        let mut src_val: Option<String> = None;
        let mut integrity_val: Option<String> = None;
        let mut has_crossorigin = false;

        for attr in attr_regex.captures_iter(attrs_str) {
            let key = attr[1].to_lowercase();
            let val = attr[2].to_string();
            match key.as_str() {
                "src" => src_val = Some(val),
                "integrity" => integrity_val = Some(val),
                "crossorigin" => has_crossorigin = true,
                _ => {}
            }
        }

        if let Some(src) = src_val {
            if src.trim().is_empty() || src.starts_with("data:") {
                continue;
            }

            let resolved_url = resolve_url(base_url, &src);
            let is_external = is_external_host(&resolved_url, base_domain);
            let has_sri = integrity_val.is_some();
            let vuln = inspect_vulnerable_libraries(&resolved_url);

            findings.push(ScriptFinding {
                resource_type: "Script (.js)",
                url: resolved_url,
                is_external,
                has_sri,
                integrity: integrity_val,
                has_crossorigin,
                vulnerable_lib: vuln,
            });
        }
    }

    // 2. Audit Stylesheets (<link rel="stylesheet">)
    for cap in link_regex.captures_iter(html) {
        let attrs_str = cap.get(1).map_or("", |m| m.as_str());

        let mut is_stylesheet = false;
        let mut href_val: Option<String> = None;
        let mut integrity_val: Option<String> = None;
        let mut has_crossorigin = false;

        for attr in attr_regex.captures_iter(attrs_str) {
            let key = attr[1].to_lowercase();
            let val = attr[2].to_string();
            match key.as_str() {
                "rel" if val.to_lowercase().contains("stylesheet") => is_stylesheet = true,
                "href" => href_val = Some(val),
                "integrity" => integrity_val = Some(val),
                "crossorigin" => has_crossorigin = true,
                _ => {}
            }
        }

        if is_stylesheet {
            if let Some(href) = href_val {
                if href.trim().is_empty() || href.starts_with("data:") {
                    continue;
                }

                let resolved_url = resolve_url(base_url, &href);
                let is_external = is_external_host(&resolved_url, base_domain);
                let has_sri = integrity_val.is_some();
                let vuln = inspect_vulnerable_libraries(&resolved_url);

                findings.push(ScriptFinding {
                    resource_type: "Stylesheet (.css)",
                    url: resolved_url,
                    is_external,
                    has_sri,
                    integrity: integrity_val,
                    has_crossorigin,
                    vulnerable_lib: vuln,
                });
            }
        }
    }

    Ok(findings)
}

fn resolve_url(base_url: &Url, relative: &str) -> String {
    if relative.starts_with("//") {
        return format!("{}:{}", base_url.scheme(), relative);
    }
    match base_url.join(relative) {
        Ok(u) => u.to_string(),
        Err(_) => relative.to_string(),
    }
}

fn is_external_host(url_str: &str, base_domain: &str) -> bool {
    if let Ok(u) = Url::parse(url_str) {
        if let Some(host) = u.host_str() {
            let host_lower = host.to_lowercase();
            return host_lower != base_domain
                && !host_lower.ends_with(&format!(".{}", base_domain));
        }
    }
    false
}

fn inspect_vulnerable_libraries(
    url_str: &str,
) -> Option<(&'static str, &'static str, &'static str)> {
    let lower = url_str.to_lowercase();

    // 1. jQuery Check (< 3.5.0 has XSS CVE-2020-11022 / CVE-2020-11023)
    if lower.contains("jquery") {
        let jq_re = Regex::new(r#"jquery[.-](\d+)\.(\d+)(?:\.(\d+))?"#).ok()?;
        if let Some(caps) = jq_re.captures(&lower) {
            let major: u32 = caps[1].parse().unwrap_or(99);
            let minor: u32 = caps[2].parse().unwrap_or(99);
            if major < 3 || (major == 3 && minor < 5) {
                return Some((
                    "jQuery",
                    "Outdated (< 3.5.0)",
                    "CVE-2020-11022 / CVE-2020-11023: Cross-site scripting (XSS) in htmlPrefilter",
                ));
            }
        }
    }

    // 2. AngularJS 1.x Check (EOL & Sandbox Escapes)
    if lower.contains("angular")
        && (lower.contains("angular.js") || lower.contains("angular.min.js"))
        && (lower.contains("/1.")
            || lower.contains("1.8.")
            || lower.contains("1.7.")
            || lower.contains("1.6.")
            || lower.contains("1.5."))
    {
        return Some((
            "AngularJS (1.x)",
            "End-of-Life (1.x)",
            "AngularJS 1.x is completely deprecated with known client-side template injection flaws",
        ));
    }

    // 3. Lodash (< 4.17.21 Prototype Pollution CVE-2021-23337)
    if lower.contains("lodash") {
        let lodash_re = Regex::new(r#"lodash[.-](\d+)\.(\d+)\.(\d+)"#).ok()?;
        if let Some(caps) = lodash_re.captures(&lower) {
            let major: u32 = caps[1].parse().unwrap_or(99);
            let minor: u32 = caps[2].parse().unwrap_or(99);
            let patch: u32 = caps[3].parse().unwrap_or(99);
            if major < 4 || (major == 4 && (minor < 17 || (minor == 17 && patch < 21))) {
                return Some((
                    "Lodash",
                    "Outdated (< 4.17.21)",
                    "CVE-2021-23337: Prototype Pollution and Command Injection vulnerabilities",
                ));
            }
        }
    }

    // 4. Moment.js (< 2.29.4 ReDoS CVE-2022-31129)
    if lower.contains("moment") && lower.contains(".js") {
        let moment_re = Regex::new(r#"moment[.-](\d+)\.(\d+)\.(\d+)"#).ok()?;
        if let Some(caps) = moment_re.captures(&lower) {
            let major: u32 = caps[1].parse().unwrap_or(99);
            let minor: u32 = caps[2].parse().unwrap_or(99);
            let patch: u32 = caps[3].parse().unwrap_or(99);
            if major < 2 || (major == 2 && (minor < 29 || (minor == 29 && patch < 4))) {
                return Some((
                    "Moment.js",
                    "Outdated (< 2.29.4)",
                    "CVE-2022-31129: ReDoS vulnerability in date parsing regex",
                ));
            }
        }
    }

    None
}

fn format_report(target_url: &str, findings: &[ScriptFinding]) -> String {
    let mut report = String::new();
    report.push_str("# SecLens Client-Side Security: Scripts & SRI Audit\n\n");
    report.push_str(&format!("- **Target URL:** `{}`\n", target_url));
    report.push_str(&format!(
        "- **Total Frontend Resources Audited:** {}\n\n",
        findings.len()
    ));

    let external_count = findings.iter().filter(|f| f.is_external).count();
    let external_no_sri: Vec<&ScriptFinding> = findings
        .iter()
        .filter(|f| f.is_external && !f.has_sri)
        .collect();
    let vulnerable_libs: Vec<&ScriptFinding> = findings
        .iter()
        .filter(|f| f.vulnerable_lib.is_some())
        .collect();

    let (score, grade) = calculate_score(external_no_sri.len(), vulnerable_libs.len());

    report.push_str(&format!(
        "### Client-Side Hygiene Score: **{} / 100** (Grade: **{}**)\n\n",
        score, grade
    ));

    report.push_str("| Metric | Count | Evaluation |\n");
    report.push_str("| :--- | :---: | :--- |\n");
    report.push_str(&format!(
        "| **External CDN Resources** | `{}` | {} |\n",
        external_count,
        if external_count > 0 {
            "🌐 Third-Party CDN"
        } else {
            "🏠 First-Party Only"
        }
    ));
    report.push_str(&format!(
        "| **External Resources Missing SRI** | `{}` | {} |\n",
        external_no_sri.len(),
        if external_no_sri.is_empty() {
            "✅ 100% Protected"
        } else {
            "⚠️ CDN Tampering Risk"
        }
    ));
    report.push_str(&format!(
        "| **Vulnerable / Outdated Libraries** | `{}` | {} |\n\n",
        vulnerable_libs.len(),
        if vulnerable_libs.is_empty() {
            "✅ Clean"
        } else {
            "🚨 Known CVEs Detected"
        }
    ));

    if !vulnerable_libs.is_empty() {
        report.push_str("> [!CAUTION]\n");
        report.push_str("> **OUTDATED & VULNERABLE CLIENT LIBRARIES DETECTED!**\n");
        report.push_str("> The web page is loading client libraries with known public security advisories (XSS, Prototype Pollution, or ReDoS).\n\n");

        report.push_str("### 🚨 Known Vulnerable Client Libraries\n\n");
        report.push_str("| Library | Detected Version | Security Advisory | Resource Location |\n");
        report.push_str("| :--- | :--- | :--- | :--- |\n");

        for f in &vulnerable_libs {
            if let Some((lib, ver, advisory)) = f.vulnerable_lib {
                report.push_str(&format!(
                    "| **{}** | `{}` | {} | `{}` |\n",
                    lib, ver, advisory, f.url
                ));
            }
        }
        report.push('\n');
    }

    report.push_str("### Frontend Resources & SRI Status Matrix\n\n");
    report.push_str(
        "| Type | Source Location | Origin | SRI Protection | CrossOrigin | Assessment |\n",
    );
    report.push_str("| :--- | :--- | :---: | :---: | :---: | :--- |\n");

    for f in findings {
        let origin_badge = if f.is_external {
            "🌐 External"
        } else {
            "🏠 Local"
        };
        let sri_badge = if let Some(ref val) = f.integrity {
            let hash_algo = if val.starts_with("sha512-") {
                "SHA-512"
            } else if val.starts_with("sha384-") {
                "SHA-384"
            } else {
                "SHA-256"
            };
            format!("✅ Valid ({})", hash_algo)
        } else if f.is_external {
            "**MISSING**".to_string()
        } else {
            "N/A (Local)".to_string()
        };
        let cross_badge = if f.has_crossorigin { "Yes" } else { "No" };

        let status_desc = if f.is_external && !f.has_sri {
            "⚠️ Unverified CDN script"
        } else if f.vulnerable_lib.is_some() {
            "🚨 Vulnerable library"
        } else {
            "Normal"
        };

        report.push_str(&format!(
            "| {} | `{}` | {} | {} | {} | {} |\n",
            f.resource_type, f.url, origin_badge, sri_badge, cross_badge, status_desc
        ));
    }

    report.push_str("\n### Remediation Roadmap\n");
    report.push_str("1. **Enforce Subresource Integrity (SRI):** For all third-party CDNs (cdnjs, unpkg, jsdelivr), add cryptographic hash hashes: `integrity=\"sha384-...\" crossorigin=\"anonymous\"`.\n");
    report.push_str("2. **Upgrade Deprecated Client Libraries:** Replace legacy jQuery (<3.5.0), AngularJS (1.x), or Lodash (<4.17.21) with modern, actively maintained versions to eliminate client-side XSS vectors.\n");

    report
}

fn calculate_score(missing_sri: usize, vulns: usize) -> (u32, &'static str) {
    let mut deduction = 0;
    deduction += vulns * 30;
    deduction += missing_sri * 12;

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
