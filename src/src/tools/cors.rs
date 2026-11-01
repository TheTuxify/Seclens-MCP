use crate::engine::Engine;
use reqwest::Url;
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

    let target_host = Url::parse(&parsed_url)
        .ok()
        .and_then(|u| u.host_str().map(|s| s.to_string()))
        .unwrap_or_else(|| "target.com".to_string());

    let subdomain_bypass_probe = format!("https://{}.evil-attacker.com", target_host);

    let probes = [
        (
            "https://evil-attacker.com",
            "Arbitrary External Origin",
            "Tests if any third-party domain is blindly trusted.",
        ),
        (
            "null",
            "Null Origin Context",
            "Tests trust for sandboxed iframes (<iframe sandbox>), local HTML files, or data URIs.",
        ),
        (
            subdomain_bypass_probe.as_str(),
            "Subdomain Bypass Origin",
            "Tests flawed regex filters (e.g. unanchored target.com.evil-attacker.com).",
        ),
    ];

    let mut report = String::new();
    report.push_str("# SecLens Cross-Origin Resource Sharing (CORS) Audit\n");
    report.push_str(&format!("- **Target Endpoint:** `{}`\n", parsed_url));
    report.push_str(&format!("- **Target Hostname:** `{}`\n\n", target_host));

    report.push_str("### 1. CORS Probe Matrix\n");
    report.push_str("| Probe Origin | Scenario | Reflected ACAO | ACAC (Credentials) | Severity & Risk Assessment |\n");
    report.push_str("| :--- | :--- | :---: | :---: | :--- |\n");

    let mut critical_found = false;
    let mut high_risk_found = false;

    for (probe_origin, scenario_name, scenario_desc) in probes {
        // First try OPTIONS preflight probe
        let preflight_resp = engine
            .client
            .request(reqwest::Method::OPTIONS, &parsed_url)
            .header("Origin", probe_origin)
            .header("Access-Control-Request-Method", "GET")
            .header(
                "Access-Control-Request-Headers",
                "Authorization, Content-Type, X-Requested-With",
            )
            .send()
            .await;

        let response = match preflight_resp {
            Ok(res) if res.headers().contains_key("access-control-allow-origin") => Ok(res),
            _ => {
                // Fallback to simple GET request with Origin header
                engine
                    .client
                    .get(&parsed_url)
                    .header("Origin", probe_origin)
                    .send()
                    .await
            }
        };

        match response {
            Ok(res) => {
                let acao = res
                    .headers()
                    .get("access-control-allow-origin")
                    .and_then(|v| v.to_str().ok())
                    .unwrap_or("None");

                let acac = res
                    .headers()
                    .get("access-control-allow-credentials")
                    .and_then(|v| v.to_str().ok())
                    .unwrap_or("false");

                let has_credentials = acac.eq_ignore_ascii_case("true");
                let reflects_origin = acao == probe_origin;
                let is_wildcard = acao == "*";

                let (severity, verdict) = if reflects_origin && has_credentials {
                    critical_found = true;
                    (
                        "**CRITICAL**",
                        "Origin dynamically reflected WITH credentials! Attackers can execute authenticated cross-site data theft.",
                    )
                } else if acao == "null" && has_credentials {
                    critical_found = true;
                    (
                        "**CRITICAL**",
                        "Null origin trusted with credentials! Sandboxed iframe can exfiltrate sensitive user data.",
                    )
                } else if is_wildcard && has_credentials {
                    critical_found = true;
                    (
                        "**CRITICAL CONFIG ERROR**",
                        "Wildcard `*` combined with credentials. Blocked by browsers, but signals broken backend security logic.",
                    )
                } else if reflects_origin {
                    high_risk_found = true;
                    (
                        "**HIGH RISK**",
                        "Origin reflected without credentials. Unauthenticated endpoints and public data exposed to cross-origin reads.",
                    )
                } else if is_wildcard {
                    (
                        "**PUBLIC ACCESS**",
                        "Wildcard `*` permitted without credentials. Acceptable only for purely public endpoints.",
                    )
                } else if acao != "None" {
                    (
                        "**NOTICE**",
                        "CORS header returned with non-matching policy.",
                    )
                } else {
                    (
                        "**PASS**",
                        "Untrusted origin rejected. No permissive CORS headers exposed.",
                    )
                };

                report.push_str(&format!(
                    "| `{}` | **{}**<br>*{}* | `{}` | `{}` | {} - {} |\n",
                    probe_origin, scenario_name, scenario_desc, acao, acac, severity, verdict
                ));
            }
            Err(e) => {
                report.push_str(&format!(
                    "| `{}` | **{}** | *Error* | *Error* | Connection failed: {} |\n",
                    probe_origin, scenario_name, e
                ));
            }
        }
    }

    report.push_str("\n### 2. Remediation Recommendations\n");
    if critical_found {
        report.push_str("> [!CAUTION]\n");
        report.push_str("> **CRITICAL CORS VULNERABILITY DETECTED!**\n");
        report.push_str("> The server reflects arbitrary `Origin` headers while allowing `Access-Control-Allow-Credentials: true`.\n");
        report.push_str("> **Remediation:** Implement a strict whitelist of authorized origins. Never echo back user-supplied `Origin` headers when credentials are true.\n");
    } else if high_risk_found {
        report.push_str("> [!WARNING]\n");
        report.push_str("> The server reflects arbitrary `Origin` headers. Ensure this endpoint returns no sensitive or user-specific data.\n");
    } else {
        report.push_str("> [!NOTE]\n");
        report.push_str(
            "> CORS configuration properly rejects untrusted external and spoofed origins.\n",
        );
    }

    Ok(report)
}
