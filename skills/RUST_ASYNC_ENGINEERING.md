# SKILL: RUST ASYNC ENGINEERING
## مهارت مهندسی هم‌روندی و شبکه ناهمگام در Rust

این مهارت راهنمای تخصصی کارایی، مدیریت حافظه و بهینه‌سازی سرعت ارتباطات شبکه با Rust و Tokio است.

---

### ۱. کلاینت اشتراکی (Shared Connection Pooling)
در اسکن‌های وب، ساخت یک کلاینت جدید برای هر ریکوئست اشتباه بزرگی است (تلف شدن زمان برای TLS Handshake مکرر). کلاینت باید در سطح استیت سرور اشتراکی باشد:

```rust
use reqwest::Client;
use std::time::Duration;

pub fn build_http_client() -> Result<Client, reqwest::Error> {
    Client::builder()
        .timeout(Duration::from_secs(8))
        .connect_timeout(Duration::from_secs(4))
        .use_rustls_tls() // Independent of system OpenSSL
        .pool_max_idle_per_host(10)
        .pool_idle_timeout(Duration::from_secs(30))
        .user_agent("SecLens-Audit/1.0 (+https://github.com/thetuxify/seclens-mcp)")
        .danger_accept_invalid_certs(false) // Strict TLS verification
        .build()
}
```

### ۲. هم‌روندی با سقف کنترل‌شده (Bounded Concurrency)
برای تست چند مسیر یا فایل حساس، ریکوئست‌ها نباید به‌صورت بی‌نهایت در هوا آزاد شوند:

```rust
use std::sync::Arc;
use tokio::sync::Semaphore;

// Limit maximum concurrent in-flight requests to 15
let semaphore = Arc::new(Semaphore::new(15));
let mut tasks = Vec::new();

for path in target_paths {
    let permit = semaphore.clone().acquire_owned().await.unwrap();
    let client = client.clone();
    let url = format!("{}/{}", base_url, path);

    tasks.push(tokio::spawn(async move {
        let _permit = permit; // Permit releases automatically on task completion
        client.get(&url).send().await
    }));
}

// Gather all results concurrently
let results = futures::future::join_all(tasks).await;
```

### ۳. مدیریت انقضا و تایم‌اوت‌های سخت‌گیرانه (Timeouts)
هیچ تسک و ریکوئستی نباید سرور را مسدود کند:
```rust
let response = tokio::time::timeout(Duration::from_secs(5), client.get(url).send()).await;
match response {
    Ok(Ok(resp)) => { /* Handle response */ },
    Ok(Err(e)) => { /* Network / HTTP error */ },
    Err(_) => { /* Timeout exceeded */ },
}
```
