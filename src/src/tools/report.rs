use crate::engine::Engine;
use crate::tools::{cors, dns_email, dns_resilience, files, headers, tls};
use chrono::Utc;
use reqwest::Url;
use serde_json::{json, Value};

pub async fn run(args: Value, engine: &Engine) -> Result<String, String> {
    let target_str = args
        .get("target")
        .and_then(|v| v.as_str())
        .ok_or_else(|| "Missing required parameter 'target'".to_string())?
        .trim();

    let (target_url, target_domain) = normalize_target(target_str);

    let include_raw_data = args
        .get("include_raw_data")
        .and_then(|v| v.as_bool())
        .unwrap_or(false);

    // 1. Concurrent Orchestration of all Sub-Audits
    let (headers_res, files_res, cors_res, email_res, dns_res, tls_res) = tokio::join!(
        headers::run(json!({ "url": target_url }), engine),
        files::run(json!({ "url": target_url }), engine),
        cors::run(json!({ "url": target_url }), engine),
        dns_email::run(json!({ "domain": target_domain })),
        dns_resilience::run(json!({ "domain": target_domain })),
        tls::run(json!({ "domain": target_domain, "port": 443 })),
    );

    // 2. Tally Findings & Compute Global Posture Score
    let mut critical_findings = Vec::new();
    let mut high_findings = Vec::new();
    let mut warn_findings = Vec::new();
    let mut pass_findings = Vec::new();

    // Analyze Headers
    match &headers_res {
        Ok(out) => {
            if out.contains("FAIL") && out.contains("HSTS") {
                high_findings.push(("CWE-319 / OWASP A02", "Missing HSTS enforcement"));
            }
            if out.contains("FAIL") && out.contains("CSP") {
                high_findings.push((
                    "CWE-79 / OWASP A03",
                    "Missing Content Security Policy (XSS vulnerability)",
                ));
            } else if out.contains("WARN") && out.contains("CSP") {
                warn_findings.push((
                    "CWE-16 / OWASP A05",
                    "Permissive CSP directives (unsafe-inline / unsafe-eval)",
                ));
            }
            if out.contains("FAIL") && out.contains("X-Frame-Options") {
                warn_findings.push((
                    "CWE-1021 / OWASP A05",
                    "Missing anti-clickjacking framing controls",
                ));
            }
            if out.contains("FAIL") && out.contains("X-Content-Type-Options") {
                warn_findings.push(("CWE-16 / OWASP A05", "MIME sniffing enabled"));
            }
            if out.contains("Server Leaks") && out.contains("WARN") {
                warn_findings.push((
                    "CWE-200 / OWASP A05",
                    "Web server software version disclosure",
                ));
            }
            pass_findings.push("Security Headers Assessment completed");
        }
        Err(e) => warn_findings.push(("Audit Error", e.as_str())),
    }

    // Analyze Files
    match &files_res {
        Ok(out) => {
            if out.contains("CRITICAL LEAK") {
                critical_findings.push((
                    "CWE-552 / OWASP A01",
                    "Publicly exposed sensitive files (.env, .git, SQL dumps, or private keys)",
                ));
            }
            if out.contains("HIGH RISK") {
                high_findings.push((
                    "CWE-200 / OWASP A01",
                    "Anomalous sensitive file endpoints accessible",
                ));
            }
            pass_findings.push("Sensitive File Exposure Audit completed");
        }
        Err(e) => warn_findings.push(("Audit Error", e.as_str())),
    }

    // Analyze CORS
    match &cors_res {
        Ok(out) => {
            if out.contains("CRITICAL") {
                critical_findings.push((
                    "CWE-942 / OWASP A01",
                    "Critical CORS misconfiguration: Arbitrary origin reflected with credentials",
                ));
            } else if out.contains("HIGH RISK") {
                high_findings.push((
                    "CWE-942 / OWASP A01",
                    "CORS origin reflected without credentials",
                ));
            }
            pass_findings.push("Cross-Origin Resource Sharing Assessment completed");
        }
        Err(e) => warn_findings.push(("Audit Error", e.as_str())),
    }

    // Analyze Email
    match &email_res {
        Ok(out) => {
            if out.contains("FAIL") && out.contains("DMARC") {
                high_findings.push(("CWE-345 / OWASP A05", "Missing DMARC anti-spoofing policy"));
            } else if out.contains("p=none") {
                warn_findings.push((
                    "CWE-345 / OWASP A05",
                    "DMARC policy in monitoring mode only (p=none)",
                ));
            }
            if out.contains("+all") {
                critical_findings.push((
                    "CWE-345 / OWASP A05",
                    "SPF record specifies +all (Permits universal email spoofing)",
                ));
            }
            pass_findings.push("Email Anti-Spoofing & Domain Health Audit completed");
        }
        Err(e) => warn_findings.push(("Audit Error", e.as_str())),
    }

    // Analyze DNS
    match &dns_res {
        Ok(out) => {
            if out.contains("DANGLING CNAME")
                || out.contains("Takeover") && out.contains("CRITICAL")
            {
                critical_findings.push((
                    "CWE-284 / OWASP A05",
                    "Dangling CNAME pointer susceptible to Subdomain Takeover",
                ));
            }
            if out.contains("CAA") && out.contains("WARN") {
                warn_findings.push((
                    "CWE-295 / OWASP A05",
                    "Missing CAA records for certificate issuance scoping",
                ));
            }
            if out.contains("DNSSEC") && out.contains("FAIL") {
                warn_findings.push(("CWE-353 / OWASP A05", "DNSSEC not enabled on target domain"));
            }
            pass_findings.push("DNS Infrastructure Resilience Assessment completed");
        }
        Err(e) => warn_findings.push(("Audit Error", e.as_str())),
    }

    // Analyze TLS
    match &tls_res {
        Ok(out) => {
            if out.contains("CRITICAL")
                && (out.contains("Expired") || out.contains("SHA1") || out.contains("MD5"))
            {
                critical_findings.push((
                    "CWE-295 / OWASP A02",
                    "Expired TLS certificate or obsolete cryptographic signature",
                ));
            }
            if out.contains("Weak Key Length") {
                high_findings.push((
                    "CWE-326 / OWASP A02",
                    "Weak cryptographic public key length in TLS certificate",
                ));
            }
            if out.contains("Expiring in") {
                warn_findings.push((
                    "Lifecycle",
                    "TLS certificate nearing expiration (< 30 days)",
                ));
            }
            pass_findings.push("TLS/SSL Cryptographic Strength Audit completed");
        }
        Err(e) => warn_findings.push(("Audit Error", e.as_str())),
    }

    // Calculate Global Security Grade
    let global_score = calculate_global_score(
        critical_findings.len(),
        high_findings.len(),
        warn_findings.len(),
    );

    let global_grade = match global_score {
        90..=100 => "A+",
        80..=89 => "A",
        65..=79 => "B",
        50..=64 => "C",
        35..=49 => "D",
        _ => "F",
    };

    // 3. Assemble Executive Markdown Report
    let mut report = String::new();
    report.push_str("# SecLens Comprehensive Security Posture Report\n");
    report.push_str(&format!("- **Target Domain:** `{}`\n", target_domain));
    report.push_str(&format!("- **Primary Endpoint:** `{}`\n", target_url));
    report.push_str(&format!(
        "- **Assessment Timestamp:** `{}`\n",
        Utc::now().to_rfc3339()
    ));
    report.push_str(&format!(
        "- **Overall Security Posture:** **{}/100** (Grade: **{}**)\n\n",
        global_score, global_grade
    ));

    // Executive Summary Box
    report.push_str("### Executive Summary\n");
    report.push_str(&format!(
        "> **Tally:** **{}** Critical | **{}** High | **{}** Medium/Low | **{}** Controls Passed\n",
        critical_findings.len(),
        high_findings.len(),
        warn_findings.len(),
        pass_findings.len()
    ));

    if !critical_findings.is_empty() {
        report.push_str(">\n> [!CAUTION]\n");
        report.push_str("> **CRITICAL SECURITY RISKS IDENTIFIED!**\n");
        report.push_str("> Immediate executive attention is required. The target exposes vulnerabilities that allow direct data exfiltration, account takeover, or infrastructure compromise.\n");
    } else if !high_findings.is_empty() {
        report.push_str(">\n> [!WARNING]\n");
        report.push_str("> **SIGNIFICANT VULNERABILITIES DETECTED.**\n");
        report.push_str("> The target has security posture deficiencies that should be prioritized during the current engineering sprint.\n");
    } else {
        report.push_str(">\n> [!NOTE]\n");
        report.push_str("> **STRONG DEFENSIVE POSTURE.**\n");
        report.push_str("> The perimeter demonstrates robust baseline controls with no critical exposures detected.\n");
    }

    // Section 1: OWASP & CWE Risk Mapping Table
    report.push_str("\n### 1. Risk Mapping & Vulnerability Index\n");
    report.push_str("| Threat Category / CWE | Severity | Vulnerability / Exposure Finding |\n");
    report.push_str("| :--- | :---: | :--- |\n");

    for (cwe, desc) in &critical_findings {
        report.push_str(&format!("| `{}` | **CRITICAL** | {} |\n", cwe, desc));
    }
    for (cwe, desc) in &high_findings {
        report.push_str(&format!("| `{}` | **HIGH** | {} |\n", cwe, desc));
    }
    for (cwe, desc) in &warn_findings {
        report.push_str(&format!("| `{}` | **MEDIUM** | {} |\n", cwe, desc));
    }
    if critical_findings.is_empty() && high_findings.is_empty() && warn_findings.is_empty() {
        report.push_str(
            "| *None* | **PASS** | No known OWASP Top 10 perimeter flaws identified. |\n",
        );
    }

    // Section 2: Tactical Remediation Roadmap
    report.push_str("\n### 2. Tactical Remediation Roadmap\n");
    report.push_str("| Priority | Timeframe | Action Item | Target Vulnerability |\n");
    report.push_str("| :---: | :---: | :--- | :--- |\n");

    if !critical_findings.is_empty() {
        report.push_str("| **P0** | `< 24 Hours` | Restrict public access to leaked sensitive files and patch critical CORS reflections. | Data Leakage / Takeover |\n");
    }
    if !high_findings.is_empty() {
        report.push_str("| **P1** | `< 7 Days` | Enforce Strict-Transport-Security (HSTS), deploy Content-Security-Policy (CSP), and configure DMARC to `p=reject`. | XSS / MitM / Email Spoofing |\n");
    }
    report.push_str("| **P2** | `< 30 Days` | Implement CAA DNS records, enable DNSSEC cryptographic signing, and prune dangling cloud CNAMEs. | DNS Spoofing / Subdomain Takeover |\n");

    // Section 3: Detailed Technical Audit Evidence
    if include_raw_data {
        report.push_str("\n---\n## Technical Audit Evidence & Sub-module Reports\n\n");

        if let Ok(h) = headers_res {
            report.push_str("### A. Security Headers Audit\n");
            report.push_str(&h);
            report.push_str("\n\n");
        }
        if let Ok(f) = files_res {
            report.push_str("### B. Sensitive File Exposure Audit\n");
            report.push_str(&f);
            report.push_str("\n\n");
        }
        if let Ok(c) = cors_res {
            report.push_str("### C. Cross-Origin Resource Sharing (CORS) Audit\n");
            report.push_str(&c);
            report.push_str("\n\n");
        }
        if let Ok(e) = email_res {
            report.push_str("### D. Email Anti-Spoofing & SPF/DMARC Audit\n");
            report.push_str(&e);
            report.push_str("\n\n");
        }
        if let Ok(d) = dns_res {
            report.push_str("### E. DNS Resilience & CAA/DNSSEC Audit\n");
            report.push_str(&d);
            report.push_str("\n\n");
        }
        if let Ok(t) = tls_res {
            report.push_str("### F. TLS/SSL Certificate Audit\n");
            report.push_str(&t);
            report.push_str("\n\n");
        }
    } else {
        report.push_str("\n> *Tip: Pass `\"include_raw_data\": true` in arguments to view complete sub-module markdown audit tables.*\n");
    }

    Ok(report)
}

fn normalize_target(target: &str) -> (String, String) {
    let clean = target.trim();
    if clean.starts_with("http://") || clean.starts_with("https://") {
        let domain = Url::parse(clean)
            .ok()
            .and_then(|u| u.host_str().map(|s| s.to_string()))
            .unwrap_or_else(|| {
                clean
                    .trim_start_matches("https://")
                    .trim_start_matches("http://")
                    .split('/')
                    .next()
                    .unwrap_or(clean)
                    .to_string()
            });
        (clean.to_string(), domain)
    } else {
        let domain = clean.split('/').next().unwrap_or(clean).to_string();
        let url = format!("https://{}", domain);
        (url, domain)
    }
}

fn calculate_global_score(critical: usize, high: usize, warn: usize) -> i32 {
    let mut score = 100;
    score -= (critical as i32) * 25;
    score -= (high as i32) * 12;
    score -= (warn as i32) * 4;
    score.clamp(0, 100)
}
