use crate::engine::Engine;
use futures::future::join_all;
use serde_json::Value;
use std::sync::Arc;
use std::time::Duration;
use tokio::sync::Semaphore;

#[derive(Debug, Clone)]
enum BucketStatus {
    OpenListing(String),
    PublicWeb,
    ProtectedAccessDenied,
    RedirectRegional(String),
    NotFound,
    Error(String),
}

#[derive(Debug, Clone)]
struct BucketProbeResult {
    provider: &'static str,
    bucket_name: String,
    url: String,
    http_status: Option<u16>,
    status: BucketStatus,
}

pub async fn run(args: Value, engine: &Engine) -> Result<String, String> {
    let target_raw = args
        .get("target_name")
        .and_then(|v| v.as_str())
        .ok_or_else(|| "Missing required parameter 'target_name'".to_string())?
        .trim();

    let target_clean = sanitize_target_name(target_raw);
    if target_clean.len() < 3 {
        return Err("Target name must be at least 3 characters long".to_string());
    }

    let bucket_candidates = generate_candidates(&target_clean);
    let mut probe_targets = Vec::new();

    for name in &bucket_candidates {
        // AWS S3
        probe_targets.push((
            "AWS S3",
            name.clone(),
            format!("https://{}.s3.amazonaws.com", name),
        ));
        // Google Cloud Storage
        probe_targets.push((
            "Google Cloud (GCS)",
            name.clone(),
            format!("https://storage.googleapis.com/{}", name),
        ));
        // Azure Blob Storage
        probe_targets.push((
            "Azure Blob",
            name.clone(),
            format!("https://{}.blob.core.windows.net", name),
        ));
        // DigitalOcean Spaces
        probe_targets.push((
            "DigitalOcean Spaces",
            name.clone(),
            format!("https://{}.nyc3.digitaloceanspaces.com", name),
        ));
    }

    let semaphore = Arc::new(Semaphore::new(10));
    let mut tasks = Vec::new();

    for (provider, name, url) in probe_targets {
        let sem = semaphore.clone();
        let client = engine.client.clone();

        tasks.push(tokio::spawn(async move {
            let _permit = match sem.acquire().await {
                Ok(p) => p,
                Err(_) => {
                    return BucketProbeResult {
                        provider,
                        bucket_name: name,
                        url,
                        http_status: None,
                        status: BucketStatus::Error("Semaphore permit failure".to_string()),
                    };
                }
            };

            probe_bucket(provider, name, url, client).await
        }));
    }

    let results: Vec<BucketProbeResult> = join_all(tasks)
        .await
        .into_iter()
        .filter_map(|r| r.ok())
        .collect();

    Ok(format_report(target_raw, &bucket_candidates, &results))
}

fn sanitize_target_name(raw: &str) -> String {
    let mut s = raw.to_lowercase();
    if let Some(pos) = s.find("://") {
        s = s[pos + 3..].to_string();
    }
    if let Some(pos) = s.find('/') {
        s = s[..pos].to_string();
    }
    // Clean domain extensions if user passed example.com
    s = s
        .replace(".com", "")
        .replace(".org", "")
        .replace(".net", "")
        .replace(".io", "")
        .replace(".dev", "")
        .replace(".ir", "")
        .replace(".co", "");

    s.chars()
        .filter(|c| c.is_ascii_alphanumeric() || *c == '-' || *c == '_')
        .collect::<String>()
        .replace('_', "-")
        .trim_matches('-')
        .to_string()
}

fn generate_candidates(base: &str) -> Vec<String> {
    let mut list = Vec::new();
    list.push(base.to_string());

    let suffixes = [
        "-backup", "-data", "-public", "-assets", "-dev", "-prod", "-media",
    ];

    for s in suffixes {
        let candidate = format!("{}{}", base, s);
        if candidate.len() <= 63 {
            list.push(candidate);
        }
    }

    list
}

async fn probe_bucket(
    provider: &'static str,
    bucket_name: String,
    url: String,
    client: reqwest::Client,
) -> BucketProbeResult {
    let resp = client
        .get(&url)
        .timeout(Duration::from_secs(4))
        .send()
        .await;

    match resp {
        Ok(r) => {
            let status_code = r.status().as_u16();
            let body = r.text().await.unwrap_or_default();
            let body_preview = if body.len() > 2048 {
                &body[..2048]
            } else {
                &body
            };

            let status = match status_code {
                200 => {
                    if body_preview.contains("<ListBucketResult>")
                        || body_preview.contains("<Contents>")
                        || body_preview.contains("<Key>")
                        || body_preview.contains("<EnumerationResults>")
                        || body_preview.contains("\"items\": [")
                    {
                        let snippet = extract_evidence(body_preview);
                        BucketStatus::OpenListing(snippet)
                    } else {
                        BucketStatus::PublicWeb
                    }
                }
                403 => BucketStatus::ProtectedAccessDenied,
                301 | 307 => {
                    let endpoint = if let Some(start) = body_preview.find("<Endpoint>") {
                        let sub = &body_preview[start + 10..];
                        if let Some(end) = sub.find("</Endpoint>") {
                            sub[..end].to_string()
                        } else {
                            "Regional Redirect".to_string()
                        }
                    } else {
                        "Regional Redirect".to_string()
                    };
                    BucketStatus::RedirectRegional(endpoint)
                }
                404 => BucketStatus::NotFound,
                other => BucketStatus::Error(format!("Unexpected HTTP {}", other)),
            };

            BucketProbeResult {
                provider,
                bucket_name,
                url,
                http_status: Some(status_code),
                status,
            }
        }
        Err(e) => {
            let err_str = e.to_string();
            let status = if err_str.contains("dns") || err_str.contains("resolve") {
                BucketStatus::NotFound
            } else {
                BucketStatus::Error(err_str)
            };

            BucketProbeResult {
                provider,
                bucket_name,
                url,
                http_status: None,
                status,
            }
        }
    }
}

fn extract_evidence(body: &str) -> String {
    if let Some(start) = body.find("<Key>") {
        let sub = &body[start + 5..];
        if let Some(end) = sub.find("</Key>") {
            return format!("Leaked key example: '{}'", &sub[..end]);
        }
    }
    if let Some(start) = body.find("<Name>") {
        let sub = &body[start + 6..];
        if let Some(end) = sub.find("</Name>") {
            return format!("Bucket root name: '{}'", &sub[..end]);
        }
    }
    "XML directory listing exposed".to_string()
}

fn format_report(target: &str, candidates: &[String], results: &[BucketProbeResult]) -> String {
    let mut report = String::new();
    report.push_str("# SecLens Cloud Security: Storage Bucket Exposure Audit\n\n");
    report.push_str(&format!("- **Target Identifier:** `{}`\n", target));
    report.push_str(&format!(
        "- **Evaluated Name Permutations ({}):** {}\n",
        candidates.len(),
        candidates
            .iter()
            .map(|c| format!("`{}`", c))
            .collect::<Vec<_>>()
            .join(", ")
    ));
    report.push_str(&format!(
        "- **Total Storage Probes Dispatched:** {}\n\n",
        results.len()
    ));

    let mut open_buckets = Vec::new();
    let mut protected_buckets = Vec::new();
    let mut error_count = 0;

    for r in results {
        match &r.status {
            BucketStatus::OpenListing(_) | BucketStatus::PublicWeb => open_buckets.push(r),
            BucketStatus::ProtectedAccessDenied | BucketStatus::RedirectRegional(_) => {
                protected_buckets.push(r)
            }
            BucketStatus::Error(err_msg) => {
                if !err_msg.is_empty() {
                    error_count += 1;
                }
            }
            BucketStatus::NotFound => {}
        }
    }

    report.push_str("### Executive Exposure Summary\n\n");
    report.push_str("| Assessment Category | Count | Status Badge |\n");
    report.push_str("| :--- | :---: | :--- |\n");
    report.push_str(&format!(
        "| **Public Unauthenticated Leaks (200 OK)** | `{}` | {} |\n",
        open_buckets.len(),
        if open_buckets.is_empty() {
            "✅ Clean"
        } else {
            "🚨 CRITICAL EXPOSURE"
        }
    ));
    report.push_str(&format!(
        "| **Protected Active Buckets (403 / Redirect)** | `{}` | 🛡️ Active Asset |\n",
        protected_buckets.len()
    ));
    report.push_str(&format!(
        "| **Non-Existent / Available Buckets (404)** | `{}` | ⚪ Unregistered |\n",
        results
            .iter()
            .filter(|r| matches!(r.status, BucketStatus::NotFound))
            .count()
    ));
    if error_count > 0 {
        report.push_str(&format!(
            "| **Unreachable / Network Errors** | `{}` | ⚠️ Network Blocked |\n",
            error_count
        ));
    }
    report.push('\n');

    if !open_buckets.is_empty() {
        report.push_str("> [!CAUTION]\n");
        report.push_str("> **CRITICAL CLOUD DATA LEAK DETECTED!**\n");
        report.push_str("> One or more cloud storage buckets are publicly accessible without authentication. Attackers can enumerate, read, or exfiltrate private enterprise files.\n\n");

        report.push_str("### 🚨 Publicly Leaked Cloud Storage Buckets\n\n");
        report.push_str("| Cloud Provider | Bucket Identifier | Probe Endpoint | Status | Exposure Finding | Severity |\n");
        report.push_str("| :--- | :--- | :--- | :---: | :--- | :---: |\n");

        for b in &open_buckets {
            let (desc, sev) = match &b.status {
                BucketStatus::OpenListing(ev) => (
                    format!("**OPEN DIRECTORY LISTING:** {}", ev),
                    "**CRITICAL**",
                ),
                BucketStatus::PublicWeb => (
                    "Public static hosting container accessible".to_string(),
                    "HIGH",
                ),
                _ => ("Publicly accessible".to_string(), "HIGH"),
            };

            report.push_str(&format!(
                "| {} | `{}` | `{}` | `{}` | {} | {} |\n",
                b.provider,
                b.bucket_name,
                b.url,
                b.http_status.unwrap_or(200),
                desc,
                sev
            ));
        }
        report.push('\n');
    }

    if !protected_buckets.is_empty() {
        report.push_str("### Active Protected Cloud Buckets (Access Denied / 403)\n\n");
        report.push_str(
            "| Cloud Provider | Bucket Identifier | Probe Endpoint | Status | Behavior Summary |\n",
        );
        report.push_str("| :--- | :--- | :--- | :---: | :--- |\n");

        for b in &protected_buckets {
            let behavior = match &b.status {
                BucketStatus::ProtectedAccessDenied => {
                    "Protected: Exists on cloud provider; anonymous listing is blocked (AccessDenied)."
                }
                BucketStatus::RedirectRegional(ep) => {
                    &format!("Redirect: Active in another cloud region ('{}').", ep)
                }
                _ => "Active bucket detected.",
            };

            report.push_str(&format!(
                "| {} | `{}` | `{}` | `{}` | {} |\n",
                b.provider,
                b.bucket_name,
                b.url,
                b.http_status.unwrap_or(403),
                behavior
            ));
        }
        report.push('\n');
    }

    if open_buckets.is_empty() && protected_buckets.is_empty() {
        report.push_str("> **NO EXPOSED STORAGE FOUND:** None of the tested permutations on AWS S3, Google Cloud Storage, Azure Blob, or DigitalOcean Spaces returned open directory listings or registered buckets.\n\n");
    }

    report.push_str("### Remediation & Defense Recommendations\n");
    report.push_str("1. **AWS S3:** Enable **S3 Block Public Access** at both AWS Account and Bucket levels. Enforce TLS via bucket policy (`aws:SecureTransport: true`).\n");
    report.push_str("2. **Google Cloud Storage:** Enable **Uniform Bucket-Level Access (UBLA)** and audit IAM permissions to ensure neither `allUsers` nor `allAuthenticatedUsers` hold `Storage Object Viewer`.\n");
    report.push_str("3. **Azure Blob Storage:** Disable **Allow Blob public access** in Azure Storage Account configuration to prevent anonymous container enumeration.\n");

    report
}
