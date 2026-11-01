use crate::engine::Engine;
use reqwest::header::HeaderMap;
use serde_json::Value;

pub async fn run(args: Value, engine: &Engine) -> Result<String, String> {
    let url_str = args
        .get("url")
        .and_then(|v| v.as_str())
        .ok_or_else(|| "Missing required parameter 'url'".to_string())?;

    let parsed_url = if !url_str.starts_with("http://") && !url_str.starts_with("https://") {
        format!("https://{}", url_str)
    } else {
        url_str.to_string()
    };

    let response = engine
        .client
        .get(&parsed_url)
        .send()
        .await
        .map_err(|e| format!("Failed to connect to {}: {}", parsed_url, e))?;

    let status = response.status();
    let headers = response.headers().clone();

    // 1. Evaluate Headers & Scoring
    let mut score: i32 = 0;
    let mut header_rows = Vec::new();

    // HSTS (20 pts)
    let (hsts_status, hsts_val, hsts_desc, hsts_pts) = evaluate_hsts(&headers);
    score += hsts_pts;
    header_rows.push((
        "Strict-Transport-Security (HSTS)",
        hsts_status,
        hsts_val,
        hsts_desc,
    ));

    // CSP (25 pts)
    let (csp_status, csp_val, csp_desc, csp_pts, csp_details) = evaluate_csp(&headers);
    score += csp_pts;
    header_rows.push((
        "Content-Security-Policy (CSP)",
        csp_status,
        csp_val,
        csp_desc,
    ));

    // X-Frame-Options (15 pts)
    let (xfo_status, xfo_val, xfo_desc, xfo_pts) = evaluate_xfo(&headers);
    score += xfo_pts;
    header_rows.push(("X-Frame-Options", xfo_status, xfo_val, xfo_desc));

    // X-Content-Type-Options (10 pts)
    let (xcto_status, xcto_val, xcto_desc, xcto_pts) = evaluate_xcto(&headers);
    score += xcto_pts;
    header_rows.push(("X-Content-Type-Options", xcto_status, xcto_val, xcto_desc));

    // Referrer-Policy (10 pts)
    let (ref_status, ref_val, ref_desc, ref_pts) = evaluate_referrer(&headers);
    score += ref_pts;
    header_rows.push(("Referrer-Policy", ref_status, ref_val, ref_desc));

    // Permissions-Policy (10 pts)
    let (perm_status, perm_val, perm_desc, perm_pts) = evaluate_permissions(&headers);
    score += perm_pts;
    header_rows.push(("Permissions-Policy", perm_status, perm_val, perm_desc));

    // Server Info Leakage (10 pts)
    let (leak_status, leak_val, leak_desc, leak_pts) = evaluate_leakage(&headers);
    score += leak_pts;
    header_rows.push((
        "Server & Technology Disclosure",
        leak_status,
        leak_val,
        leak_desc,
    ));

    // 2. Cookie Security Analysis
    let cookies = evaluate_cookies(&headers);
    for c in &cookies {
        if !c.http_only {
            score -= 5;
        }
        if !c.secure {
            score -= 5;
        }
        if c.same_site.is_none() || c.same_site.as_deref() == Some("None") && !c.secure {
            score -= 3;
        }
    }

    let final_score = score.clamp(0, 100);
    let grade = match final_score {
        95..=100 => "A+",
        85..=94 => "A",
        70..=84 => "B",
        55..=69 => "C",
        40..=54 => "D",
        _ => "F",
    };

    // 3. Assemble Markdown Report
    let mut report = String::new();
    report.push_str("# SecLens Security Headers Audit\n");
    report.push_str(&format!("- **Target:** `{}`\n", parsed_url));
    report.push_str(&format!("- **HTTP Status:** `{}`\n", status));
    report.push_str(&format!(
        "- **Overall Security Score:** **{}/100** (Grade: **{}**)\n\n",
        final_score, grade
    ));

    report.push_str("### 1. HTTP Defense Headers Matrix\n");
    report.push_str(
        "| Security Header | Status | Observed Value | Risk Assessment & Remediation |\n",
    );
    report.push_str("| :--- | :---: | :--- | :--- |\n");

    for (name, st, val, desc) in header_rows {
        report.push_str(&format!(
            "| `{}` | **{}** | `{}` | {} |\n",
            name, st, val, desc
        ));
    }

    // CSP Deep Inspection
    if let Some(details) = csp_details {
        report.push_str("\n### 2. Deep Content-Security-Policy (CSP) Inspection\n");
        report.push_str(&details);
    }

    // Cookie Security Table
    report.push_str("\n### 3. Cookie Security & Flag Analysis\n");
    if cookies.is_empty() {
        report.push_str("*No `Set-Cookie` response headers observed for this endpoint.*\n");
    } else {
        report.push_str("| Cookie Name | HttpOnly | Secure | SameSite | Verdict |\n");
        report.push_str("| :--- | :---: | :---: | :---: | :--- |\n");
        for c in cookies {
            let ho_str = if c.http_only {
                "**PASS**"
            } else {
                "**FAIL** (XSS Risk)"
            };
            let sec_str = if c.secure {
                "**PASS**"
            } else {
                "**FAIL** (Cleartext Risk)"
            };
            let ss_str = c.same_site.as_deref().unwrap_or("None (Missing)");
            let verdict = if c.http_only && c.secure && c.same_site.is_some() {
                "Fully Hardened"
            } else {
                "Vulnerable to tampering or interception"
            };
            report.push_str(&format!(
                "| `{}` | {} | {} | `{}` | {} |\n",
                c.name, ho_str, sec_str, ss_str, verdict
            ));
        }
    }

    Ok(report)
}

fn evaluate_hsts(headers: &HeaderMap) -> (&'static str, String, &'static str, i32) {
    if let Some(val) = headers
        .get("strict-transport-security")
        .and_then(|v| v.to_str().ok())
    {
        if val.contains("max-age=") && val.contains("includeSubDomains") {
            (
                "PASS",
                val.to_string(),
                "HTTPS enforced strictly across all subdomains with preload eligibility.",
                20,
            )
        } else {
            (
                "WARN",
                val.to_string(),
                "HSTS present but missing `includeSubDomains` or `preload`.",
                10,
            )
        }
    } else {
        (
            "FAIL",
            "Not Found".to_string(),
            "Missing HSTS! High risk of SSL-stripping and MitM attacks.",
            0,
        )
    }
}

fn evaluate_csp(headers: &HeaderMap) -> (&'static str, String, &'static str, i32, Option<String>) {
    if let Some(val) = headers
        .get("content-security-policy")
        .and_then(|v| v.to_str().ok())
    {
        let lower = val.to_lowercase();
        let has_default_src = lower.contains("default-src");
        let has_unsafe_inline = lower.contains("'unsafe-inline'");
        let has_unsafe_eval = lower.contains("'unsafe-eval'");
        let has_frame_ancestors = lower.contains("frame-ancestors");
        let has_base_uri = lower.contains("base-uri");
        let has_wildcard_script =
            lower.contains("script-src *") || lower.contains("script-src 'self' *");

        let mut details = String::new();
        details.push_str("| Directive / Check | Finding | Security Implication |\n");
        details.push_str("| :--- | :---: | :--- |\n");

        if has_default_src {
            details.push_str("| `default-src` | **PASS** | Fallback policy defined for unlisted resource types. |\n");
        } else {
            details.push_str(
                "| `default-src` | **WARN** | Missing fallback default-src directive. |\n",
            );
        }

        if has_unsafe_inline {
            details.push_str("| `unsafe-inline` | **WARN** | Allows execution of inline scripts/styles (XSS vector). |\n");
        } else {
            details
                .push_str("| `unsafe-inline` | **PASS** | Inline script execution disallowed. |\n");
        }

        if has_unsafe_eval {
            details.push_str("| `unsafe-eval` | **WARN** | Allows dynamic code evaluation like `eval()` (Injection vector). |\n");
        } else {
            details.push_str(
                "| `unsafe-eval` | **PASS** | Dynamic code string evaluation disabled. |\n",
            );
        }

        if has_frame_ancestors {
            details.push_str("| `frame-ancestors` | **PASS** | Modern anti-clickjacking framing controls configured. |\n");
        } else {
            details.push_str("| `frame-ancestors` | **WARN** | Missing frame-ancestors; rely on legacy X-Frame-Options. |\n");
        }

        if has_base_uri {
            details.push_str("| `base-uri` | **PASS** | Prevents HTML `<base>` tag injection and script hijack. |\n");
        } else {
            details.push_str("| `base-uri` | **WARN** | Missing base-uri restriction. |\n");
        }

        if has_wildcard_script {
            details.push_str("| `Wildcard Script` | **FAIL** | Script execution permitted from unrestricted origins `*`. |\n");
        }

        let is_clean =
            has_default_src && !has_unsafe_inline && !has_unsafe_eval && !has_wildcard_script;
        if is_clean {
            (
                "PASS",
                truncate(val, 45),
                "Comprehensive CSP configured with restrictive boundaries.",
                25,
                Some(details),
            )
        } else {
            ("WARN", truncate(val, 45), "CSP defined but contains weak directives (unsafe-inline/eval or missing default-src).", 12, Some(details))
        }
    } else {
        (
            "FAIL",
            "Not Found".to_string(),
            "Vulnerable to Cross-Site Scripting (XSS), data injection, and rogue script inclusion.",
            0,
            None,
        )
    }
}

fn evaluate_xfo(headers: &HeaderMap) -> (&'static str, String, &'static str, i32) {
    if let Some(val) = headers.get("x-frame-options").and_then(|v| v.to_str().ok()) {
        let upper = val.to_uppercase();
        if upper.contains("DENY") || upper.contains("SAMEORIGIN") {
            (
                "PASS",
                val.to_string(),
                "Protected against UI redressing and clickjacking frames.",
                15,
            )
        } else {
            (
                "WARN",
                val.to_string(),
                "Non-standard X-Frame-Options value. Prefer DENY or SAMEORIGIN.",
                8,
            )
        }
    } else {
        (
            "FAIL",
            "Not Found".to_string(),
            "Missing anti-framing header; site can be framed in rogue iframes.",
            0,
        )
    }
}

fn evaluate_xcto(headers: &HeaderMap) -> (&'static str, String, &'static str, i32) {
    if let Some(val) = headers
        .get("x-content-type-options")
        .and_then(|v| v.to_str().ok())
    {
        if val.eq_ignore_ascii_case("nosniff") {
            (
                "PASS",
                "nosniff".to_string(),
                "Browser MIME sniffing disabled.",
                10,
            )
        } else {
            (
                "WARN",
                val.to_string(),
                "Expected exact directive `nosniff`.",
                5,
            )
        }
    } else {
        (
            "FAIL",
            "Not Found".to_string(),
            "Browser may sniff response content-types (MIME confusion).",
            0,
        )
    }
}

fn evaluate_referrer(headers: &HeaderMap) -> (&'static str, String, &'static str, i32) {
    if let Some(val) = headers.get("referrer-policy").and_then(|v| v.to_str().ok()) {
        let lower = val.to_lowercase();
        if lower.contains("no-referrer") || lower.contains("strict-origin") {
            (
                "PASS",
                val.to_string(),
                "Strict referrer boundary prevents leak of query parameters.",
                10,
            )
        } else {
            (
                "WARN",
                val.to_string(),
                "Permissive Referrer-Policy configured.",
                5,
            )
        }
    } else {
        (
            "WARN",
            "Not Found".to_string(),
            "Sensitive path parameters may leak in HTTP Referer header.",
            0,
        )
    }
}

fn evaluate_permissions(headers: &HeaderMap) -> (&'static str, String, &'static str, i32) {
    if let Some(val) = headers
        .get("permissions-policy")
        .and_then(|v| v.to_str().ok())
    {
        (
            "PASS",
            truncate(val, 45),
            "Browser hardware APIs and device sensors restricted.",
            10,
        )
    } else {
        (
            "WARN",
            "Not Found".to_string(),
            "Browser capabilities (mic, camera, location) not scoped.",
            0,
        )
    }
}

fn evaluate_leakage(headers: &HeaderMap) -> (&'static str, String, &'static str, i32) {
    let server = headers.get("server").and_then(|v| v.to_str().ok());
    let x_powered = headers.get("x-powered-by").and_then(|v| v.to_str().ok());

    match (server, x_powered) {
        (Some(s), Some(x)) => (
            "WARN",
            format!("Server: {}, X-Powered-By: {}", s, x),
            "Exact server software and framework versions exposed to attackers.",
            0,
        ),
        (Some(s), None) => (
            "WARN",
            format!("Server: {}", s),
            "Web server technology disclosed. Conceal banner in production.",
            3,
        ),
        (None, Some(x)) => (
            "WARN",
            format!("X-Powered-By: {}", x),
            "Backend framework revealed. Remove header in app config.",
            3,
        ),
        (None, None) => (
            "PASS",
            "Concealed".to_string(),
            "No server or framework technology signatures detected.",
            10,
        ),
    }
}

struct CookieFinding {
    name: String,
    http_only: bool,
    secure: bool,
    same_site: Option<String>,
}

fn evaluate_cookies(headers: &HeaderMap) -> Vec<CookieFinding> {
    let mut findings = Vec::new();

    for val in headers.get_all("set-cookie") {
        if let Ok(cookie_str) = val.to_str() {
            let parts: Vec<&str> = cookie_str.split(';').map(|s| s.trim()).collect();
            if parts.is_empty() {
                continue;
            }

            let name_part = parts[0];
            let cookie_name = name_part
                .split('=')
                .next()
                .unwrap_or(name_part)
                .trim()
                .to_string();

            let mut http_only = false;
            let mut secure = false;
            let mut same_site = None;

            for attr in &parts[1..] {
                let lower = attr.to_lowercase();
                if lower == "httponly" {
                    http_only = true;
                } else if lower == "secure" {
                    secure = true;
                } else if lower.starts_with("samesite=") {
                    let ss_val = attr.split('=').nth(1).unwrap_or("").trim();
                    same_site = Some(ss_val.to_string());
                }
            }

            findings.push(CookieFinding {
                name: cookie_name,
                http_only,
                secure,
                same_site,
            });
        }
    }

    findings
}

fn truncate(s: &str, max: usize) -> String {
    if s.len() > max {
        format!("{}...", &s[..max])
    } else {
        s.to_string()
    }
}
