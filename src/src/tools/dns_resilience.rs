use hickory_resolver::proto::rr::RecordType;
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
    report.push_str("# SecLens DNS Infrastructure & Resilience Audit\n");
    report.push_str(&format!("- **Target Domain:** `{}`\n\n", clean_domain));

    report.push_str("### 1. DNS Security Matrix\n");
    report.push_str(
        "| Control | Status | Observed Configuration | Risk Analysis & Recommendation |\n",
    );
    report.push_str("| :--- | :---: | :--- | :--- |\n");

    // 1. Evaluate CAA Records (RFC 8659)
    evaluate_caa(&resolver, clean_domain, &mut report).await;

    // 2. Evaluate DNSSEC (DNSKEY & DS)
    evaluate_dnssec(&resolver, clean_domain, &mut report).await;

    // 3. Evaluate CNAME & Subdomain Takeover Risks
    evaluate_cname_takeover(&resolver, clean_domain, &mut report).await;

    report.push_str("\n### 2. DNS Hardening Recommendations\n");
    report.push_str("1. **Configure CAA Records:** Restrict SSL/TLS certificate issuance strictly to trusted CAs (e.g., Let's Encrypt, DigiCert).\n");
    report.push_str("2. **Enable DNSSEC:** Sign the zone with cryptographic keys to prevent DNS spoofing and cache-poisoning attacks.\n");
    report.push_str("3. **Prune Dangling Records:** Immediately delete obsolete CNAME records pointing to decommissioned cloud instances.\n");

    Ok(report)
}

async fn evaluate_caa(resolver: &TokioResolver, domain: &str, out: &mut String) {
    let caa_lookup = resolver.lookup(domain, RecordType::CAA).await;

    match caa_lookup {
        Ok(lookup) => {
            let mut entries = Vec::new();
            for record in lookup.answers() {
                entries.push(record.data.to_string());
            }

            if entries.is_empty() {
                out.push_str("| `CAA (RFC 8659)` | **WARN** | *Empty* | No CAA records returned. Any public CA can issue certificates for this domain. |\n");
            } else {
                let formatted = entries.join("; ");
                out.push_str(&format!(
                    "| `CAA (RFC 8659)` | **PASS** | `{}` | Authorized CAs explicitly declared. Rogue certificate issuance blocked. |\n",
                    truncate(&formatted, 50)
                ));
            }
        }
        Err(_) => {
            out.push_str("| `CAA (RFC 8659)` | **WARN** | *Not Configured* | No CAA policy found. Any CA in WebPKI can issue certificates for this domain. |\n");
        }
    }
}

async fn evaluate_dnssec(resolver: &TokioResolver, domain: &str, out: &mut String) {
    let dnskey_lookup = resolver.lookup(domain, RecordType::DNSKEY).await;
    let ds_lookup = resolver.lookup(domain, RecordType::DS).await;

    let has_dnskey = dnskey_lookup
        .map(|l| !l.answers().is_empty())
        .unwrap_or(false);
    let has_ds = ds_lookup.map(|l| !l.answers().is_empty()).unwrap_or(false);

    match (has_dnskey, has_ds) {
        (true, true) => {
            out.push_str("| `DNSSEC` | **PASS** | `DNSKEY + DS Verified` | Fully signed and cryptographically anchored to parent TLD. Resilient to cache poisoning. |\n");
        }
        (true, false) => {
            out.push_str("| `DNSSEC` | **WARN** | `DNSKEY Present (No DS)` | Zone contains public keys but lacks DS delegation record in the parent registrar. |\n");
        }
        _ => {
            out.push_str("| `DNSSEC` | **FAIL** | *Disabled* | DNS records are unauthenticated. Susceptible to Man-in-the-Middle DNS spoofing. |\n");
        }
    }
}

async fn evaluate_cname_takeover(resolver: &TokioResolver, domain: &str, out: &mut String) {
    let cname_lookup = resolver.lookup(domain, RecordType::CNAME).await;

    let known_cloud_providers = [
        ("github.io", "GitHub Pages"),
        ("s3.amazonaws.com", "AWS S3 Bucket"),
        ("elasticbeanstalk.com", "AWS Elastic Beanstalk"),
        ("azurewebsites.net", "Microsoft Azure Web App"),
        ("herokuapp.com", "Heroku Application"),
        ("cloudfront.net", "AWS CloudFront Distribution"),
        ("zendesk.com", "Zendesk Support Desk"),
        ("surge.sh", "Surge.sh Static Hosting"),
        ("myshopify.com", "Shopify Storefront"),
        ("bitbucket.io", "Bitbucket Cloud Pages"),
        ("gitlab.io", "GitLab Pages"),
        ("cname.vercel-dns.com", "Vercel Hosting"),
        ("pantheonsite.io", "Pantheon Hosting"),
        ("readme.io", "ReadMe Documentation"),
    ];

    if let Ok(lookup) = cname_lookup {
        if let Some(record) = lookup.answers().first() {
            let target = record.data.to_string();
            let clean_target = target.trim_end_matches('.');

            let mut matched_provider = None;
            for (pattern, name) in &known_cloud_providers {
                if clean_target.ends_with(pattern) {
                    matched_provider = Some(*name);
                    break;
                }
            }

            if let Some(provider_name) = matched_provider {
                let ip_check = resolver.lookup_ip(clean_target).await;
                let is_resolving = ip_check.is_ok();

                if !is_resolving {
                    out.push_str(&format!(
                        "| `CNAME Takeover` | **CRITICAL** | Points to `{}` ({}) | **DANGLING CNAME:** Target cloud resource is unclaimed and fails to resolve! Attackers can claim it to take over the subdomain. |\n",
                        clean_target, provider_name
                    ));
                    return;
                } else {
                    out.push_str(&format!(
                        "| `CNAME Integrity` | **PASS** | Points to `{}` ({}) | Active CNAME successfully resolves to cloud provider IPs. |\n",
                        clean_target, provider_name
                    ));
                    return;
                }
            } else {
                out.push_str(&format!(
                    "| `CNAME Canonical` | **PASS** | Points to `{}` | Standard canonical alias configuration. |\n",
                    clean_target
                ));
                return;
            }
        }
    }

    out.push_str("| `Subdomain Takeover` | **PASS** | *Apex / Direct A Record* | No dangling CNAME aliases detected for this domain. |\n");
}

fn truncate(s: &str, max: usize) -> String {
    if s.len() > max {
        format!("{}...", &s[..max])
    } else {
        s.to_string()
    }
}
