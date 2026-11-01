use crate::engine::Engine;
use regex::Regex;
use serde_json::{json, Value};
use std::time::Duration;

#[derive(Debug, Clone)]
struct ParsedPackage {
    name: String,
    version: String,
}

#[derive(Debug, Clone)]
struct VulnerabilityFinding {
    package: String,
    installed_version: String,
    vuln_id: String,
    severity: String,
    summary: String,
    fixed_version: Option<String>,
}

pub async fn run(args: Value, engine: &Engine) -> Result<String, String> {
    let manifest_content = args
        .get("manifest_content")
        .and_then(|v| v.as_str())
        .ok_or_else(|| "Missing required parameter 'manifest_content'".to_string())?
        .trim();

    let ecosystem_raw = args
        .get("ecosystem")
        .and_then(|v| v.as_str())
        .unwrap_or("npm")
        .trim();

    let ecosystem = normalize_ecosystem(ecosystem_raw)?;

    let packages = parse_manifest(manifest_content, ecosystem)?;
    if packages.is_empty() {
        return Err(
            "No package dependencies could be parsed from the provided manifest content"
                .to_string(),
        );
    }

    let vulns = query_osv_batch(&packages, ecosystem, engine).await?;

    Ok(format_report(ecosystem, &packages, &vulns))
}

fn normalize_ecosystem(raw: &str) -> Result<&'static str, String> {
    let lower = raw.to_lowercase();
    match lower.as_str() {
        "crates.io" | "cargo" | "rust" => Ok("crates.io"),
        "npm" | "node" | "javascript" | "yarn" => Ok("npm"),
        "pypi" | "pip" | "python" => Ok("PyPI"),
        _ => Err(format!(
            "Unsupported ecosystem '{}'. Supported: 'crates.io', 'npm', 'PyPI'",
            raw
        )),
    }
}

fn parse_manifest(content: &str, ecosystem: &str) -> Result<Vec<ParsedPackage>, String> {
    match ecosystem {
        "npm" => parse_npm(content),
        "crates.io" => parse_cargo(content),
        "PyPI" => parse_pypi(content),
        _ => Ok(Vec::new()),
    }
}

fn parse_npm(content: &str) -> Result<Vec<ParsedPackage>, String> {
    let mut packages = Vec::new();

    if let Ok(val) = serde_json::from_str::<Value>(content) {
        let mut extract_from_obj = |obj_val: &Value| {
            if let Some(map) = obj_val.as_object() {
                for (name, ver_val) in map {
                    if let Some(ver_str) = ver_val.as_str() {
                        let clean_ver = clean_version_string(ver_str);
                        if !clean_ver.is_empty() && clean_ver != "*" {
                            packages.push(ParsedPackage {
                                name: name.clone(),
                                version: clean_ver,
                            });
                        }
                    }
                }
            }
        };

        if let Some(deps) = val.get("dependencies") {
            extract_from_obj(deps);
        }
        if let Some(dev_deps) = val.get("devDependencies") {
            extract_from_obj(dev_deps);
        }

        if !packages.is_empty() {
            return Ok(packages);
        }
    }

    // Fallback line regex for package.json snippets
    let re = Regex::new(
        r#""([@a-zA-Z0-9/_-]+)"\s*:\s*"[\^~>=<v]*([0-9]+\.[0-9]+(?:\.[0-9]+)?(?:-[a-zA-Z0-9.]+)?)"#,
    )
    .map_err(|e| format!("Regex error: {}", e))?;

    for cap in re.captures_iter(content) {
        packages.push(ParsedPackage {
            name: cap[1].to_string(),
            version: cap[2].to_string(),
        });
    }

    Ok(packages)
}

fn parse_cargo(content: &str) -> Result<Vec<ParsedPackage>, String> {
    let mut packages = Vec::new();

    // Check if Cargo.lock format
    if content.contains("[[package]]") {
        let lock_re = Regex::new(r#"name\s*=\s*"([^"]+)"\s*\n\s*version\s*=\s*"([^"]+)""#)
            .map_err(|e| format!("Regex error: {}", e))?;

        for cap in lock_re.captures_iter(content) {
            packages.push(ParsedPackage {
                name: cap[1].to_string(),
                version: cap[2].to_string(),
            });
        }
        return Ok(packages);
    }

    // Cargo.toml format (e.g. serde = "1.0.197" or tokio = { version = "1.36.0" })
    let toml_re = Regex::new(r#"([a-zA-Z0-9_-]+)\s*=\s*(?:"[\^~>=<v]*([0-9]+\.[0-9]+(?:\.[0-9]+)?)"|\{\s*version\s*=\s*"[\^~>=<v]*([0-9]+\.[0-9]+(?:\.[0-9]+)?)"\s*\})"#)
        .map_err(|e| format!("Regex error: {}", e))?;

    for cap in toml_re.captures_iter(content) {
        let name = cap[1].to_string();
        let ver = cap.get(2).or_else(|| cap.get(3)).map_or("", |m| m.as_str());
        if !ver.is_empty() {
            packages.push(ParsedPackage {
                name,
                version: ver.to_string(),
            });
        }
    }

    Ok(packages)
}

fn parse_pypi(content: &str) -> Result<Vec<ParsedPackage>, String> {
    let mut packages = Vec::new();
    let pypi_re =
        Regex::new(r#"(?i)^([a-zA-Z0-9_.-]+)\s*(?:==|>=|<=|~=)\s*([0-9]+\.[0-9]+(?:\.[0-9]+)?)"#)
            .map_err(|e| format!("Regex error: {}", e))?;

    for line in content.lines() {
        let trimmed = line.trim();
        if trimmed.starts_with('#') || trimmed.is_empty() {
            continue;
        }

        if let Some(caps) = pypi_re.captures(trimmed) {
            packages.push(ParsedPackage {
                name: caps[1].to_string(),
                version: caps[2].to_string(),
            });
        }
    }

    Ok(packages)
}

fn clean_version_string(v: &str) -> String {
    v.trim_start_matches('^')
        .trim_start_matches('~')
        .trim_start_matches('>')
        .trim_start_matches('=')
        .trim_start_matches('<')
        .trim_start_matches('v')
        .trim()
        .to_string()
}

async fn query_osv_batch(
    packages: &[ParsedPackage],
    ecosystem: &str,
    engine: &Engine,
) -> Result<Vec<VulnerabilityFinding>, String> {
    // OSV Batch Query Endpoint: POST https://api.osv.dev/v1/querybatch
    let queries: Vec<Value> = packages
        .iter()
        .map(|p| {
            json!({
                "package": {
                    "name": p.name,
                    "ecosystem": ecosystem
                },
                "version": p.version
            })
        })
        .collect();

    let payload = json!({ "queries": queries });

    let resp = engine
        .client
        .post("https://api.osv.dev/v1/querybatch")
        .json(&payload)
        .timeout(Duration::from_secs(10))
        .send()
        .await
        .map_err(|e| format!("Failed to reach Google OSV API: {}", e))?;

    if !resp.status().is_success() {
        return Err(format!(
            "Google OSV API returned HTTP status {}",
            resp.status()
        ));
    }

    let resp_val: Value = resp
        .json()
        .await
        .map_err(|e| format!("Failed to parse OSV JSON response: {}", e))?;

    let mut raw_pairs = Vec::new();
    let mut unique_ids = std::collections::HashSet::new();

    if let Some(results_arr) = resp_val.get("results").and_then(|r| r.as_array()) {
        for (idx, res) in results_arr.iter().enumerate() {
            let pkg = match packages.get(idx) {
                Some(p) => p,
                None => continue,
            };

            if let Some(vulns_arr) = res.get("vulns").and_then(|v| v.as_array()) {
                for vuln in vulns_arr {
                    if let Some(vid) = vuln.get("id").and_then(|id| id.as_str()) {
                        raw_pairs.push((pkg.clone(), vid.to_string()));
                        if unique_ids.len() < 12 {
                            unique_ids.insert(vid.to_string());
                        }
                    }
                }
            }
        }
    }

    // Concurrently enrich detailed vulnerability summaries from OSV API
    let mut details_map = std::collections::HashMap::new();
    let mut enrich_tasks = Vec::new();

    for vid in unique_ids {
        let client = engine.client.clone();
        enrich_tasks.push(tokio::spawn(async move {
            let url = format!("https://api.osv.dev/v1/vulns/{}", vid);
            if let Ok(resp) = client
                .get(&url)
                .timeout(Duration::from_secs(5))
                .send()
                .await
            {
                if let Ok(val) = resp.json::<Value>().await {
                    return (vid, Some(val));
                }
            }
            (vid, None)
        }));
    }

    for res in futures::future::join_all(enrich_tasks)
        .await
        .into_iter()
        .flatten()
    {
        if let (vid, Some(val)) = res {
            details_map.insert(vid, val);
        }
    }

    let mut findings = Vec::new();
    for (pkg, vid) in raw_pairs {
        if let Some(detail) = details_map.get(&vid) {
            let cve = detail
                .get("aliases")
                .and_then(|a| a.as_array())
                .and_then(|arr| {
                    arr.iter().find_map(|v| {
                        let s = v.as_str().unwrap_or("");
                        if s.starts_with("CVE-") {
                            Some(s)
                        } else {
                            None
                        }
                    })
                });

            let display_id = match cve {
                Some(cve_str) => format!("{} / {}", vid, cve_str),
                None => vid.clone(),
            };

            let summary = detail
                .get("summary")
                .or_else(|| detail.get("details"))
                .and_then(|s| s.as_str())
                .unwrap_or("Security vulnerability reported in upstream package")
                .to_string();

            let severity = extract_severity(detail);
            let fixed_ver = extract_fixed_version(detail);

            findings.push(VulnerabilityFinding {
                package: pkg.name,
                installed_version: pkg.version,
                vuln_id: display_id,
                severity,
                summary: truncate_string(&summary, 80),
                fixed_version: fixed_ver,
            });
        } else {
            findings.push(VulnerabilityFinding {
                package: pkg.name,
                installed_version: pkg.version,
                vuln_id: vid,
                severity: "HIGH".to_string(),
                summary: "Security vulnerability reported in package".to_string(),
                fixed_version: None,
            });
        }
    }

    Ok(findings)
}

fn extract_severity(vuln: &Value) -> String {
    if let Some(db_sev) = vuln
        .get("database_specific")
        .and_then(|db| db.get("severity"))
        .and_then(|s| s.as_str())
    {
        return db_sev.to_uppercase();
    }

    if let Some(sev_arr) = vuln.get("severity").and_then(|s| s.as_array()) {
        if let Some(first) = sev_arr.first() {
            if let Some(score) = first.get("score").and_then(|sc| sc.as_str()) {
                return format!("CVSS {}", score);
            }
        }
    }

    "HIGH".to_string()
}

fn extract_fixed_version(vuln: &Value) -> Option<String> {
    if let Some(affected_arr) = vuln.get("affected").and_then(|a| a.as_array()) {
        for aff in affected_arr {
            if let Some(ranges) = aff.get("ranges").and_then(|r| r.as_array()) {
                for range in ranges {
                    if let Some(events) = range.get("events").and_then(|e| e.as_array()) {
                        for ev in events {
                            if let Some(fixed) = ev.get("fixed").and_then(|f| f.as_str()) {
                                return Some(fixed.to_string());
                            }
                        }
                    }
                }
            }
        }
    }
    None
}

fn truncate_string(s: &str, max_len: usize) -> String {
    let clean = s.replace('\n', " ").replace('\r', "");
    if clean.len() > max_len {
        format!("{}...", &clean[..max_len])
    } else {
        clean
    }
}

fn format_report(
    ecosystem: &str,
    packages: &[ParsedPackage],
    findings: &[VulnerabilityFinding],
) -> String {
    let mut report = String::new();
    report.push_str("# SecLens Supply Chain: Dependencies Security Audit (Google OSV)\n\n");
    report.push_str(&format!("- **Ecosystem:** `{}`\n", ecosystem));
    report.push_str(&format!(
        "- **Audited Dependencies:** `{}`\n",
        packages.len()
    ));
    report.push_str(&format!(
        "- **Identified Vulnerabilities:** `{}`\n\n",
        findings.len()
    ));

    let crit_count = findings
        .iter()
        .filter(|f| f.severity.contains("CRITICAL"))
        .count();
    let high_count = findings
        .iter()
        .filter(|f| f.severity.contains("HIGH"))
        .count();

    report.push_str("### Executive Supply Chain Posture\n\n");
    report.push_str("| Metric | Value |\n");
    report.push_str("| :--- | :---: |\n");
    report.push_str(&format!(
        "| **Critical Vulnerabilities** | `{}` |\n",
        crit_count
    ));
    report.push_str(&format!("| **High Severity Flaws** | `{}` |\n", high_count));
    report.push_str(&format!(
        "| **Total Security Advisories** | `{}` |\n\n",
        findings.len()
    ));

    if findings.is_empty() {
        report.push_str("> **PASS: No known vulnerabilities found!** All audited dependencies are clean according to Google's Open Source Vulnerabilities (OSV) database.\n\n");
    } else {
        report.push_str("> [!CAUTION]\n");
        report.push_str("> **KNOWN VULNERABILITIES IDENTIFIED IN DEPENDENCIES!**\n");
        report.push_str("> Several packages in your manifest match public security advisories (CVEs/GHSAs). Upgrade to fixed versions immediately to avoid supply chain exploitation.\n\n");

        report.push_str("### 🚨 Vulnerability Findings Matrix\n\n");
        report.push_str("| Package | Current Version | Vulnerability ID | Severity | Summary | Recommended Fixed Version |\n");
        report.push_str("| :--- | :---: | :--- | :---: | :--- | :---: |\n");

        for f in findings {
            let fixed = f.fixed_version.as_deref().unwrap_or("Check upstream");
            report.push_str(&format!(
                "| `{}` | `{}` | `{}` | **{}** | {} | `{}` |\n",
                f.package, f.installed_version, f.vuln_id, f.severity, f.summary, fixed
            ));
        }
        report.push('\n');
    }

    report.push_str("### Audited Package Manifest Roster\n\n");
    report.push_str("| # | Package Name | Specified Version |\n");
    report.push_str("| :-: | :--- | :---: |\n");

    for (i, p) in packages.iter().enumerate() {
        report.push_str(&format!("| {} | `{}` | `{}` |\n", i + 1, p.name, p.version));
    }

    report.push_str("\n### Supply Chain Remediation Roadmap\n");
    report.push_str("1. **Bump Vulnerable Packages:** Run package manager upgrade commands (`cargo update`, `npm audit fix`, or `pip install --upgrade -r requirements.txt`).\n");
    report.push_str("2. **Lockfile Integrity:** Commit `Cargo.lock` / `package-lock.json` to source control to lock deterministic dependency trees.\n");
    report.push_str("3. **CI/CD Vulnerability Scanning:** Integrate SecLens into automated pull request checks to prevent vulnerable dependencies from entering production.\n");

    report
}
