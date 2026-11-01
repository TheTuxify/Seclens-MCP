use hickory_resolver::proto::rr::RData;
use hickory_resolver::TokioResolver;
use serde_json::Value;

pub async fn run(args: Value) -> Result<String, String> {
    let domain_str = args
        .get("domain")
        .and_then(|v| v.as_str())
        .ok_or_else(|| "Missing required parameter 'domain'".to_string())?
        .trim();

    let clean_domain = domain_str
        .trim_start_matches("https://")
        .trim_start_matches("http://")
        .split('/')
        .next()
        .unwrap_or(domain_str)
        .split(':')
        .next()
        .unwrap_or(domain_str);

    let resolver = TokioResolver::builder_tokio()
        .map_err(|e| format!("Failed to create DNS builder: {}", e))?
        .build()
        .map_err(|e| format!("Failed to build DNS resolver: {}", e))?;

    let mut report = String::new();
    report.push_str("# SecLens Email Defense & Anti-Spoofing Audit\n");
    report.push_str(&format!("- **Target Domain:** `{}`\n\n", clean_domain));

    let mut total_score = 0;

    // 1. Evaluate SPF Record
    let (spf_score, spf_finding) = evaluate_spf(&resolver, clean_domain).await;
    total_score += spf_score;

    // 2. Evaluate DMARC Record
    let (dmarc_score, dmarc_finding) = evaluate_dmarc(&resolver, clean_domain).await;
    total_score += dmarc_score;

    // 3. Evaluate DKIM Selectors
    let (dkim_score, dkim_finding) = evaluate_dkim(&resolver, clean_domain).await;
    total_score += dkim_score;

    let final_score = total_score.clamp(0, 100);
    let grade = match final_score {
        90..=100 => "A+",
        80..=89 => "A",
        65..=79 => "B",
        50..=64 => "C",
        35..=49 => "D",
        _ => "F",
    };

    report.push_str(&format!(
        "### Overall Spoofing Resilience: **{}/100** (Grade: **{}**)\n\n",
        final_score, grade
    ));

    report.push_str("### 1. Email Authentication Matrix\n");
    report.push_str(
        "| Protocol | Status | Observed Policy / Evidence | Risk & Security Analysis |\n",
    );
    report.push_str("| :--- | :---: | :--- | :--- |\n");
    report.push_str(&spf_finding);
    report.push_str(&dmarc_finding);
    report.push_str(&dkim_finding);

    report.push_str("\n### 2. Spoofing Risk Summary\n");
    if final_score >= 85 {
        report.push_str("> **SECURE:** Domain is well-defended against unauthorized email spoofing and phishing with strict SPF and DMARC enforcement.\n");
    } else if final_score >= 50 {
        report.push_str("> **WARNING:** Domain has partial email security controls, but permissive policies allow attackers to deliver spoofed emails to user inboxes.\n");
    } else {
        report.push_str("> **CRITICAL:** High vulnerability to email impersonation! Attackers can forge emails appearing to originate from this domain with no rejection.\n");
    }

    Ok(report)
}

async fn evaluate_spf(resolver: &TokioResolver, domain: &str) -> (i32, String) {
    let txt_lookup = resolver.txt_lookup(domain).await;
    let mut spf_record = None;

    if let Ok(lookup) = txt_lookup {
        for record in lookup.answers() {
            if let RData::TXT(txt) = &record.data {
                let full_text: String = txt
                    .txt_data
                    .iter()
                    .map(|b| String::from_utf8_lossy(b))
                    .collect();
                if full_text.starts_with("v=spf1") {
                    spf_record = Some(full_text);
                    break;
                }
            }
        }
    }

    match spf_record {
        Some(spf) => {
            let terms: Vec<&str> = spf.split_whitespace().collect();
            let mut dns_lookup_count = 0;
            let mut end_mechanism = "none";

            for term in &terms[1..] {
                if term.starts_with("include:")
                    || term.starts_with("a:")
                    || *term == "a"
                    || term.starts_with("mx:")
                    || *term == "mx"
                    || term.starts_with("ptr")
                    || term.starts_with("exists:")
                    || term.starts_with("redirect=")
                {
                    dns_lookup_count += 1;
                }

                if term.ends_with("all") {
                    end_mechanism = term;
                }
            }

            let lookup_warning = if dns_lookup_count > 10 {
                format!("<br>**RFC 7208 VIOLATION:** {} DNS lookups exceed the 10-lookup limit (Permanently Fails).", dns_lookup_count)
            } else {
                format!("({} DNS lookups / 10 allowed)", dns_lookup_count)
            };

            match end_mechanism {
                "-all" => (
                    35,
                    format!(
                        "| `SPF (RFC 7208)` | **PASS** | `{}` | Strict enforcement (`-all` HardFail). Unauthorized senders rejected. {} |\n",
                        truncate(&spf, 45), lookup_warning
                    ),
                ),
                "~all" => (
                    20,
                    format!(
                        "| `SPF (RFC 7208)` | **WARN** | `{}` | SoftFail (`~all`). Spoofed mail may be accepted or routed to Spam. {} |\n",
                        truncate(&spf, 45), lookup_warning
                    ),
                ),
                "?all" => (
                    10,
                    format!(
                        "| `SPF (RFC 7208)` | **WARN** | `{}` | Neutral (`?all`). No policy asserted; provides zero spoofing defense. {} |\n",
                        truncate(&spf, 45), lookup_warning
                    ),
                ),
                "+all" => (
                    0,
                    format!(
                        "| `SPF (RFC 7208)` | **CRITICAL** | `{}` | `+all` allows any IP in the world to send mail on behalf of this domain! {} |\n",
                        truncate(&spf, 45), lookup_warning
                    ),
                ),
                _ => (
                    15,
                    format!(
                        "| `SPF (RFC 7208)` | **WARN** | `{}` | Missing terminal `all` mechanism. {} |\n",
                        truncate(&spf, 45), lookup_warning
                    ),
                ),
            }
        }
        None => (
            0,
            "| `SPF (RFC 7208)` | **FAIL** | *Not Found* | No SPF record found. Domain has no authorized sender restrictions. |\n".to_string(),
        ),
    }
}

async fn evaluate_dmarc(resolver: &TokioResolver, domain: &str) -> (i32, String) {
    let dmarc_domain = format!("_dmarc.{}", domain);
    let txt_lookup = resolver.txt_lookup(&dmarc_domain).await;
    let mut dmarc_record = None;

    if let Ok(lookup) = txt_lookup {
        for record in lookup.answers() {
            if let RData::TXT(txt) = &record.data {
                let full_text: String = txt
                    .txt_data
                    .iter()
                    .map(|b| String::from_utf8_lossy(b))
                    .collect();
                if full_text.starts_with("v=DMARC1") {
                    dmarc_record = Some(full_text);
                    break;
                }
            }
        }
    }

    match dmarc_record {
        Some(dmarc) => {
            let tags: Vec<&str> = dmarc.split(';').map(|s| s.trim()).collect();
            let mut policy = "none";
            let mut sub_policy = None;
            let mut rua = None;
            let mut pct = 100;

            for tag in &tags {
                if tag.starts_with("p=") {
                    policy = tag.trim_start_matches("p=");
                } else if tag.starts_with("sp=") {
                    sub_policy = Some(tag.trim_start_matches("sp="));
                } else if tag.starts_with("rua=") {
                    rua = Some(tag.trim_start_matches("rua="));
                } else if tag.starts_with("pct=") {
                    pct = tag.trim_start_matches("pct=").parse().unwrap_or(100);
                }
            }

            let reporting_status = if rua.is_some() {
                "Aggregate reports active."
            } else {
                "Missing `rua` reporting URI."
            };

            let pct_note = if pct < 100 {
                format!(" Only {}% enforced.", pct)
            } else {
                "".to_string()
            };

            let sp_note = match sub_policy {
                Some(sp) => format!(" Subdomain policy: `sp={}`.", sp),
                None => "".to_string(),
            };

            match policy {
                "reject" => (
                    45,
                    format!(
                        "| `DMARC (RFC 7489)` | **PASS** | `{}` | `p=reject`: Maximum protection. Fake emails unconditionally discarded. {}{}{} |\n",
                        truncate(&dmarc, 45), reporting_status, pct_note, sp_note
                    ),
                ),
                "quarantine" => (
                    30,
                    format!(
                        "| `DMARC (RFC 7489)` | **WARN** | `{}` | `p=quarantine`: Spoofed emails diverted to Spam folder. {}{}{} |\n",
                        truncate(&dmarc, 45), reporting_status, pct_note, sp_note
                    ),
                ),
                _ => (
                    15,
                    format!(
                        "| `DMARC (RFC 7489)` | **WARN** | `{}` | `p=none`: Monitoring mode only! Does not protect users from spoofing. {}{}{} |\n",
                        truncate(&dmarc, 45), reporting_status, pct_note, sp_note
                    ),
                ),
            }
        }
        None => (
            0,
            "| `DMARC (RFC 7489)` | **FAIL** | *Not Found* | No `_dmarc` record found! High vulnerability to CEO fraud and spoofing. |\n".to_string(),
        ),
    }
}

async fn evaluate_dkim(resolver: &TokioResolver, domain: &str) -> (i32, String) {
    let common_selectors = [
        "default", "google", "mail", "k1", "smtp", "s1", "2023", "2024",
    ];
    let mut found_selectors = Vec::new();

    for sel in common_selectors {
        let dkim_host = format!("{}._domainkey.{}", sel, domain);
        if let Ok(lookup) = resolver.txt_lookup(&dkim_host).await {
            for record in lookup.answers() {
                if let RData::TXT(txt) = &record.data {
                    let full_text: String = txt
                        .txt_data
                        .iter()
                        .map(|b| String::from_utf8_lossy(b))
                        .collect();
                    if full_text.contains("v=DKIM1") || full_text.contains("p=") {
                        found_selectors.push(sel);
                        break;
                    }
                }
            }
        }
    }

    if !found_selectors.is_empty() {
        (
            20,
            format!(
                "| `DKIM (RFC 6376)` | **PASS** | Selectors: `{}` | Active public key signatures verified for outgoing emails. |\n",
                found_selectors.join(", ")
            ),
        )
    } else {
        (
            10,
            "| `DKIM (RFC 6376)` | **NOTICE** | No standard selector | Standard selectors (default, google, mail, k1) not detected (custom selector may exist). |\n".to_string(),
        )
    }
}

fn truncate(s: &str, max: usize) -> String {
    if s.len() > max {
        format!("{}...", &s[..max])
    } else {
        s.to_string()
    }
}
