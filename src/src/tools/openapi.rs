use crate::engine::Engine;
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
        .map_err(|e| format!("Failed to fetch OpenAPI spec from {}: {}", parsed_url, e))?;

    let spec_json: Value = response.json().await.map_err(|e| {
        format!(
            "Failed to parse response as JSON OpenAPI specification: {}",
            e
        )
    })?;

    // 1. Extract Spec Metadata
    let title = spec_json
        .get("info")
        .and_then(|i| i.get("title"))
        .and_then(|t| t.as_str())
        .unwrap_or("API Specification");
    let version = spec_json
        .get("info")
        .and_then(|i| i.get("version"))
        .and_then(|v| v.as_str())
        .unwrap_or("unknown");
    let openapi_ver = spec_json
        .get("openapi")
        .or_else(|| spec_json.get("swagger"))
        .and_then(|v| v.as_str())
        .unwrap_or("3.0");

    // 2. Global Security Schemes
    let has_global_security = spec_json
        .get("security")
        .and_then(|s| s.as_array())
        .map(|arr| !arr.is_empty())
        .unwrap_or(false);

    let security_schemes = extract_security_schemes(&spec_json);

    // 3. Inspect Paths & Operations
    let mut findings = Vec::new();
    let mut total_operations = 0;

    let debug_admin_keywords = [
        "admin",
        "debug",
        "internal",
        "actuator",
        "metrics",
        "env",
        "config",
        "manage",
        "dump",
        "shell",
        "terminal",
        "system",
        "healthcheck",
        "test",
        "staging",
    ];

    if let Some(paths) = spec_json.get("paths").and_then(|p| p.as_object()) {
        for (path_name, path_item) in paths {
            if let Some(methods) = path_item.as_object() {
                for (method, op_val) in methods {
                    let method_upper = method.to_uppercase();
                    if !["GET", "POST", "PUT", "DELETE", "PATCH", "HEAD", "OPTIONS"]
                        .contains(&method_upper.as_str())
                    {
                        continue;
                    }

                    total_operations += 1;

                    // Check security on this operation
                    let op_security = op_val.get("security").and_then(|s| s.as_array());
                    let is_unauthenticated = match op_security {
                        Some(arr) => arr.is_empty(),
                        None => !has_global_security,
                    };

                    // Check for admin/debug keywords in route
                    let lower_path = path_name.to_lowercase();
                    let matched_keyword = debug_admin_keywords
                        .iter()
                        .find(|&&kw| lower_path.contains(kw));

                    if let Some(kw) = matched_keyword {
                        if is_unauthenticated {
                            findings.push((
                                path_name.clone(),
                                method_upper.clone(),
                                "CRITICAL",
                                format!(
                                    "Unauthenticated sensitive route matching '{}'! Direct public access without auth.",
                                    kw
                                ),
                            ));
                        } else {
                            findings.push((
                                path_name.clone(),
                                method_upper.clone(),
                                "MEDIUM",
                                format!(
                                    "Sensitive '{}' administrative route exposed in public OpenAPI documentation.",
                                    kw
                                ),
                            ));
                        }
                    } else if is_unauthenticated {
                        if ["DELETE", "PUT", "PATCH"].contains(&method_upper.as_str()) {
                            findings.push((
                                path_name.clone(),
                                method_upper.clone(),
                                "HIGH",
                                "State-modifying / destructive HTTP method without security scheme requirement.".to_string(),
                            ));
                        } else if method_upper == "POST" {
                            findings.push((
                                path_name.clone(),
                                method_upper.clone(),
                                "WARN",
                                "Resource creation (POST) endpoint missing explicit security requirement.".to_string(),
                            ));
                        }
                    }
                }
            }
        }
    }

    // 4. Assemble Report
    let mut report = String::new();
    report.push_str("# SecLens OpenAPI / Swagger Security Audit\n");
    report.push_str(&format!(
        "- **Specification:** `{}` (v{})\n",
        title, version
    ));
    report.push_str(&format!("- **OpenAPI Standard:** `{}`\n", openapi_ver));
    report.push_str(&format!(
        "- **Total Operations Analyzed:** `{}`\n",
        total_operations
    ));
    report.push_str(&format!(
        "- **Global Security Configured:** {}\n",
        if has_global_security {
            "**YES**"
        } else {
            "**NO (Default Open)**"
        }
    ));
    report.push_str(&format!(
        "- **Declared Auth Schemes:** `{}`\n\n",
        if security_schemes.is_empty() {
            "None".to_string()
        } else {
            security_schemes.join(", ")
        }
    ));

    report.push_str("### 1. API Security Findings & Exposure Table\n");
    if findings.is_empty() {
        report.push_str(
            "> **PASS:** All endpoints enforce security policies, with no unauthenticated destructive routes or debug endpoints detected.\n",
        );
    } else {
        report.push_str(
            "| Endpoint Route | HTTP Method | Severity | Exposure / Vulnerability Description |\n",
        );
        report.push_str("| :--- | :---: | :---: | :--- |\n");
        for (p, m, sev, desc) in &findings {
            let sev_badge = match *sev {
                "CRITICAL" => "**CRITICAL**",
                "HIGH" => "**HIGH**",
                "MEDIUM" => "**MEDIUM**",
                _ => "**WARN**",
            };
            report.push_str(&format!(
                "| `{}` | `{}` | {} | {} |\n",
                p, m, sev_badge, desc
            ));
        }
    }

    report.push_str("\n### 2. Remediation Checklist\n");
    report.push_str("1. Ensure root-level `security` array is defined in OpenAPI spec to enforce authentication by default.\n");
    report.push_str("2. Remove all internal/debug endpoints (`/actuator`, `/admin`, `/dump`) from publicly facing Swagger UI docs.\n");
    report.push_str("3. Explicitly verify role-based access control (RBAC) on all destructive methods (DELETE, PUT, PATCH).\n");

    Ok(report)
}

fn extract_security_schemes(spec: &Value) -> Vec<String> {
    let mut schemes = Vec::new();

    // OpenAPI 3.x: components.securitySchemes
    if let Some(comp_schemes) = spec
        .get("components")
        .and_then(|c| c.get("securitySchemes"))
        .and_then(|s| s.as_object())
    {
        for (name, val) in comp_schemes {
            let scheme_type = val
                .get("type")
                .and_then(|t| t.as_str())
                .unwrap_or("unknown");
            schemes.push(format!("{} ({})", name, scheme_type));
        }
    }

    // Swagger 2.0: securityDefinitions
    if let Some(sec_defs) = spec.get("securityDefinitions").and_then(|s| s.as_object()) {
        for (name, val) in sec_defs {
            let scheme_type = val
                .get("type")
                .and_then(|t| t.as_str())
                .unwrap_or("unknown");
            schemes.push(format!("{} ({})", name, scheme_type));
        }
    }

    schemes
}
