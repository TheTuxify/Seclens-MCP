use reqwest::Client;
use std::time::Duration;

#[derive(Clone)]
pub struct Engine {
    pub client: Client,
}

impl Engine {
    pub fn new() -> Result<Self, reqwest::Error> {
        let client = Client::builder()
            .timeout(Duration::from_secs(8))
            .connect_timeout(Duration::from_secs(4))
            .use_rustls_tls()
            .pool_max_idle_per_host(10)
            .pool_idle_timeout(Duration::from_secs(30))
            .user_agent("SecLens-Security-Audit/1.0 (+https://github.com/thetuxify/seclens-mcp)")
            .redirect(reqwest::redirect::Policy::limited(5))
            .build()?;

        Ok(Self { client })
    }
}
