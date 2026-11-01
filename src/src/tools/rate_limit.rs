use crate::engine::Engine;
use reqwest::header::HeaderMap;
use reqwest::Url;
use serde_json::Value;
use std::time::{Duration, Instant};

#[derive(Debug, Clone)]
struct ProbeStep {
    attempt: usize,
    status_code: u16,
    duration_ms: u128,
    remaining_header: Option<String>,
    limit_header: Option<String>,
    retry_after: Option<String>,
}

pub async fn run(args: Value, engine: &Engine) -> Result<String, String> {
    let url_str = args
        .get("url")
        .and_then(|v| v.as_str())
        .ok_or_else(|| "Missing required parameter 'url'".to_string())?
        .trim();

    let target_url =
        Url::parse(url_str).map_err(|e| format!("Invalid URL '{}': {}", url_str, e))?;

    let probes_count = args
        .get("probes_count")
        .and_then(|v| v.as_u64())
        .unwrap_or(5)
        .clamp(3, 15) as usize;

    let mut steps = Vec::new();
    let mut saw_429 = false;

    for i in 1..=probes_count {
        let start = Instant::now();
        let resp_result = engine
            .client
            .get(target_url.clone())
            .timeout(Duration::from_secs(5))
            .send()
            .await;

        let duration_ms = start.elapsed().as_millis();

        match resp_result {
            Ok(resp) => {
                let status_code = resp.status().as_u16();
                if status_code == 429 {
                    saw_429 = true;
                }

                let (limit, remaining, retry_after) = extract_ratelimit_headers(resp.headers());

                steps.push(ProbeStep {
                    attempt: i,
                    status_code,
                    duration_ms,
                    remaining_header: remaining,
                    limit_header: limit,
                    retry_after,
                });
            }
            Err(e) => {
                return Err(format!("Probe #{} failed with network error: {}", i, e));
            }
        }

        // Small delay to simulate rapid sequential requests without saturating host
        if i < probes_count {
            tokio::time::sleep(Duration::from_millis(60)).await;
        }
    }

    Ok(format_report(url_str, probes_count, saw_429, &steps))
}

fn extract_ratelimit_headers(
    headers: &HeaderMap,
) -> (Option<String>, Option<String>, Option<String>) {
    let limit_keys = ["ratelimit-limit", "x-ratelimit-limit", "x-rate-limit-limit"];
    let remaining_keys = [
        "ratelimit-remaining",
        "x-ratelimit-remaining",
        "x-rate-limit-remaining",
    ];
    let retry_keys = ["retry-after", "ratelimit-reset", "x-ratelimit-reset"];

    let limit = limit_keys.iter().find_map(|&k| {
        headers
            .get(k)
            .and_then(|v| v.to_str().ok())
            .map(|s| s.to_string())
    });

    let remaining = remaining_keys.iter().find_map(|&k| {
        headers
            .get(k)
            .and_then(|v| v.to_str().ok())
            .map(|s| s.to_string())
    });

    let retry = retry_keys.iter().find_map(|&k| {
        headers
            .get(k)
            .and_then(|v| v.to_str().ok())
            .map(|s| s.to_string())
    });

    (limit, remaining, retry)
}

fn format_report(
    target_url: &str,
    probes_count: usize,
    saw_429: bool,
    steps: &[ProbeStep],
) -> String {
    let mut report = String::new();
    report.push_str("# SecLens Traffic Security: Rate-Limiting Resilience Audit\n\n");
    report.push_str(&format!("- **Target URL:** `{}`\n", target_url));
    report.push_str(&format!(
        "- **Sequential Rapid Probes Dispatched:** `{}`\n\n",
        probes_count
    ));

    let has_headers = steps
        .iter()
        .any(|s| s.remaining_header.is_some() || s.limit_header.is_some());
    let mut is_decrementing = false;
    let mut prev_remaining: Option<i64> = None;

    for s in steps {
        if let Some(ref r_str) = s.remaining_header {
            if let Ok(val) = r_str.parse::<i64>() {
                if let Some(prev) = prev_remaining {
                    if val < prev {
                        is_decrementing = true;
                    }
                }
                prev_remaining = Some(val);
            }
        }
    }

    report.push_str("### Executive Posture Evaluation\n\n");
    report.push_str("| Metric | Observed Behavior | Assessment |\n");
    report.push_str("| :--- | :---: | :--- |\n");
    report.push_str(&format!(
        "| **HTTP 429 (Too Many Requests)** | {} | {} |\n",
        if saw_429 {
            "🚨 **TRIGGERED**"
        } else {
            "Not Triggered"
        },
        if saw_429 {
            "Active rate-limiting threshold enforced"
        } else {
            "No throttling encountered during burst"
        }
    ));
    report.push_str(&format!(
        "| **Rate-Limit Telemetry Headers** | {} | {} |\n",
        if has_headers {
            "✅ Present"
        } else {
            "❌ Missing"
        },
        if has_headers {
            "Standard RateLimit or X-RateLimit headers broadcasted"
        } else {
            "Server exposes no rate-limiting metadata"
        }
    ));
    report.push_str(&format!(
        "| **Quota Decrement Tracking** | {} | {} |\n\n",
        if is_decrementing {
            "✅ Decrementing"
        } else {
            "Static / N/A"
        },
        if is_decrementing {
            "Server actively tracked probe consumption"
        } else {
            "No quota decrements observed"
        }
    ));

    if !saw_429 && !has_headers {
        report.push_str("> [!WARNING]\n");
        report.push_str("> **NO RATE-LIMITING PROTECTION DETECTED!**\n");
        report.push_str("> The endpoint accepted repeated rapid bursts without rate-limiting headers or HTTP 429 throttling. This leaves the service vulnerable to automated brute-force attacks, credential stuffing, and application-layer DoS.\n\n");
    } else {
        report.push_str("> [!NOTE]\n");
        report.push_str("> **ACTIVE RATE-LIMITING DEFENSE:** The server provides rate-limiting telemetry or throttles requests.\n\n");
    }

    report.push_str("### Sequential Probe Telemetry Matrix\n\n");
    report.push_str(
        "| Probe # | Status | Latency | Limit Header | Remaining Quota | Retry-After / Reset |\n",
    );
    report.push_str("| :---: | :---: | :---: | :---: | :---: | :---: |\n");

    for s in steps {
        let status_badge = if s.status_code == 429 {
            "**429 Too Many Requests**"
        } else if s.status_code >= 200 && s.status_code < 300 {
            "200 OK"
        } else {
            &format!("{}", s.status_code)
        };

        let lim = s.limit_header.as_deref().unwrap_or("-");
        let rem = s.remaining_header.as_deref().unwrap_or("-");
        let retry = s.retry_after.as_deref().unwrap_or("-");

        report.push_str(&format!(
            "| #{} | {} | {} ms | `{}` | `{}` | `{}` |\n",
            s.attempt, status_badge, s.duration_ms, lim, rem, retry
        ));
    }

    report.push_str("\n### Engineering Recommendations\n");
    report.push_str("1. **Implement Token Bucket or Leaky Bucket:** Configure rate limits at the edge (Cloudflare WAF, AWS WAF, or Nginx `limit_req_zone $binary_remote_addr zone=api_limit:10m rate=10r/s;`).\n");
    report.push_str("2. **Standardize Rate-Limit Headers:** Return IETF standard `RateLimit-Limit`, `RateLimit-Remaining`, and `RateLimit-Reset` headers so legitimate API clients can backoff gracefully.\n");
    report.push_str("3. **Protect Authentication Endpoints:** Apply stricter per-IP or per-username throttling on login, password-reset, and OTP verification endpoints.\n");

    report
}
