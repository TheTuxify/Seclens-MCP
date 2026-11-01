use regex::Regex;
use serde_json::Value;
use std::fs;
use std::path::Path;

struct SecretPattern {
    name: &'static str,
    regex: Regex,
}

pub async fn run(args: Value) -> Result<String, String> {
    let path_str = args.get("path").and_then(|v| v.as_str()).unwrap_or(".");

    let patterns = build_patterns()?;
    let high_entropy_regex = Regex::new(r#"[A-Za-z0-9+/=_-]{24,}"#)
        .map_err(|e| format!("Failed to compile high-entropy regex: {}", e))?;

    let mut report = String::new();
    report.push_str("# SecLens Static Secrets & Credentials Audit\n");
    report.push_str(&format!("- **Scan Root Directory:** `{}`\n\n", path_str));
    report.push_str(
        "| File Path | Line # | Secret Type | Entropy | Masked Evidence (Safe Display) |\n",
    );
    report.push_str("| :--- | :---: | :--- | :---: | :--- |\n");

    let mut findings_count = 0;
    scan_dir(
        Path::new(path_str),
        &patterns,
        &high_entropy_regex,
        &mut report,
        &mut findings_count,
        0,
    )?;

    report.push_str("\n### Executive Findings Summary\n");
    if findings_count == 0 {
        report.push_str("> **CLEAN:** No leaked API keys, database connection strings, private certificates, or high-entropy tokens were detected in scanned files.\n");
    } else {
        report.push_str(&format!(
            "> **WARNING: Found {} potential hardcoded secret(s)!**\n> Hardcoded credentials in source control present severe security risks. Immediately revoke, rotate, and migrate credentials to a secure secret manager (e.g. Vault, AWS Secrets Manager, or environment variables).\n",
            findings_count
        ));
    }

    Ok(report)
}

fn build_patterns() -> Result<Vec<SecretPattern>, String> {
    let raw_defs: &[(&'static str, &'static str)] = &[
        // 1. Telegram Bot Token
        ("Telegram Bot Token", r"[0-9]{8,10}:[a-zA-Z0-9_-]{35}"),
        // 2. OpenAI API Key
        (
            "OpenAI API Key",
            r"(?:sk-[a-zA-Z0-9T3BlbkFJ]{20,}|sk-proj-[a-zA-Z0-9_-]{40,})",
        ),
        // 3. Anthropic Claude API Key
        ("Anthropic API Key", r"sk-ant-[a-zA-Z0-9_-]{30,}"),
        // 4. Google Gemini API Key
        ("Google Gemini API Key", r"AIza[0-9A-Za-z-_]{35}"),
        // 5. Groq Cloud API Key
        ("Groq API Key", r"gsk_[a-zA-Z0-9]{48,}"),
        // 6. Stripe Secret / Restricted Key
        (
            "Stripe Secret Key",
            r"(?:sk|rk)_(?:live|test)_[0-9a-zA-Z]{24,}",
        ),
        // 7. Slack API / Bot Token
        ("Slack Token", r"xox[baprs]-[0-9a-zA-Z]{10,48}"),
        // 8. GitHub Classic & Fine-grained Token
        (
            "GitHub Personal Token",
            r"(?:gh[pousr]_[A-Za-z0-9_]{36,255}|github_pat_[0-9a-zA-Z_]{60,})",
        ),
        // 9. AWS Access Key ID
        (
            "AWS Access Key ID",
            r"(?:A3T[A-Z0-9]|AKIA|AGPA|AIDA|AROA|AIPA|ANPA|ANVA|ASIA)[A-Z0-9]{16}",
        ),
        // 10. AWS Secret Access Key
        (
            "AWS Secret Access Key",
            r#"(?i)aws_secret_access_key\s*[:=]\s*["']?([A-Za-z0-9/+=]{40})["']?"#,
        ),
        // 11. Database Connection Strings
        (
            "Database Connection String",
            r#"(?:postgres|postgresql|mysql|mongodb(?:\+srv)?|redis|amqp)://[^\s"']+"#,
        ),
        // 12. Private Cryptographic Key Block
        (
            "Private Cryptographic Key",
            r"-----BEGIN (?:RSA |EC |OPENSSH |DSA |PGP )?PRIVATE KEY(?: BLOCK)?-----",
        ),
        // 13. Hardcoded JWT Token
        (
            "Hardcoded JWT Token",
            r"eyJ[A-Za-z0-9_-]{10,}\.eyJ[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}",
        ),
        // 14. Hardcoded Generic Password / Auth Secret
        (
            "Hardcoded Password Assignment",
            r#"(?i)(?:password|passwd|api_secret|secret_key|auth_token)\s*[:=]\s*["']([^"']{8,})["']"#,
        ),
    ];

    let mut patterns = Vec::with_capacity(raw_defs.len());
    for (name, pat_str) in raw_defs {
        let regex = Regex::new(pat_str)
            .map_err(|e| format!("Failed to compile pattern '{}': {}", name, e))?;
        patterns.push(SecretPattern { name, regex });
    }

    Ok(patterns)
}

fn scan_dir(
    dir: &Path,
    patterns: &[SecretPattern],
    high_entropy_regex: &Regex,
    out: &mut String,
    count: &mut usize,
    depth: usize,
) -> Result<(), String> {
    if depth > 10 || *count >= 50 {
        return Ok(());
    }

    let entries = match fs::read_dir(dir) {
        Ok(e) => e,
        Err(_) => return Ok(()),
    };

    for entry in entries.flatten() {
        let path = entry.path();
        let file_name = path.file_name().unwrap_or_default().to_string_lossy();

        // Skip non-project and build directories
        if file_name.starts_with('.')
            || file_name == "target"
            || file_name == "node_modules"
            || file_name == ".git"
            || file_name == "venv"
            || file_name == ".venv"
            || file_name == "dist"
            || file_name == "build"
        {
            continue;
        }

        if path.is_dir() {
            scan_dir(&path, patterns, high_entropy_regex, out, count, depth + 1)?;
        } else if path.is_file() {
            // Only scan text files under 2MB
            if let Ok(meta) = fs::metadata(&path) {
                if meta.len() > 2 * 1024 * 1024 {
                    continue;
                }
            }

            if let Ok(content) = fs::read_to_string(&path) {
                for (line_idx, line) in content.lines().enumerate() {
                    let mut line_matched = false;

                    // 1. Check known signature patterns
                    for pat in patterns {
                        if let Some(m) = pat.regex.find(line) {
                            *count += 1;
                            line_matched = true;
                            let matched = m.as_str();
                            let entropy = shannon_entropy(matched);
                            let masked = mask_secret(matched);

                            out.push_str(&format!(
                                "| `{}` | `{}` | **{}** | `{:.2}` | `{}` |\n",
                                path.display(),
                                line_idx + 1,
                                pat.name,
                                entropy,
                                masked
                            ));

                            if *count >= 50 {
                                return Ok(());
                            }
                        }
                    }

                    // 2. High-Entropy Scanner (Shannon Entropy > 4.5 for uncatalogued tokens)
                    if !line_matched {
                        for m in high_entropy_regex.find_iter(line) {
                            let candidate = m.as_str();
                            let entropy = shannon_entropy(candidate);

                            // Detect high-entropy candidate strings (> 4.5)
                            if entropy >= 4.5 && candidate.len() >= 24 {
                                *count += 1;
                                let masked = mask_secret(candidate);
                                out.push_str(&format!(
                                    "| `{}` | `{}` | **High-Entropy Secret** | `{:.2}` | `{}` |\n",
                                    path.display(),
                                    line_idx + 1,
                                    entropy,
                                    masked
                                ));

                                if *count >= 50 {
                                    return Ok(());
                                }
                            }
                        }
                    }
                }
            }
        }
    }

    Ok(())
}

pub fn shannon_entropy(s: &str) -> f64 {
    if s.is_empty() {
        return 0.0;
    }
    let mut counts = [0usize; 256];
    for &b in s.as_bytes() {
        counts[b as usize] += 1;
    }
    let len = s.len() as f64;
    let mut entropy = 0.0;
    for &count in &counts {
        if count > 0 {
            let p = count as f64 / len;
            entropy -= p * p.log2();
        }
    }
    entropy
}

fn mask_secret(raw: &str) -> String {
    let clean = raw.trim();
    if clean.len() <= 8 {
        return "********".to_string();
    }
    format!("{}...{}", &clean[..4], &clean[clean.len() - 4..])
}
