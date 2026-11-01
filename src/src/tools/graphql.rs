use crate::engine::Engine;
use reqwest::Url;
use serde_json::{json, Value};
use std::time::Duration;

#[derive(Debug, Clone)]
struct GraphqlEndpointResult {
    endpoint_url: String,
    status_code: Option<u16>,
    introspection_enabled: bool,
    total_types_count: usize,
    sample_types: Vec<String>,
    field_suggestions: bool,
    get_method_allowed: bool,
    playground_exposed: bool,
}

pub async fn run(args: Value, engine: &Engine) -> Result<String, String> {
    let url_str = args
        .get("url")
        .and_then(|v| v.as_str())
        .ok_or_else(|| "Missing required parameter 'url'".to_string())?
        .trim();

    let target_url =
        Url::parse(url_str).map_err(|e| format!("Invalid URL '{}': {}", url_str, e))?;

    let candidate_endpoints = resolve_graphql_candidates(&target_url);

    let mut successful_probe: Option<GraphqlEndpointResult> = None;

    for endpoint in &candidate_endpoints {
        if let Some(res) = probe_graphql_endpoint(endpoint, engine).await {
            successful_probe = Some(res);
            break; // Stop at first responsive GraphQL endpoint
        }
    }

    match successful_probe {
        Some(res) => Ok(format_report(url_str, &res)),
        None => Err(format!(
            "No responsive GraphQL endpoint detected at tested paths on '{}'",
            url_str
        )),
    }
}

fn resolve_graphql_candidates(base_url: &Url) -> Vec<String> {
    let path = base_url.path();
    if path.ends_with("/graphql") || path.ends_with("/query") {
        return vec![base_url.to_string()];
    }

    let origin = format!(
        "{}://{}",
        base_url.scheme(),
        base_url.host_str().unwrap_or("localhost")
    );

    vec![
        format!("{}/graphql", origin),
        format!("{}/api/graphql", origin),
        format!("{}/v1/graphql", origin),
        format!("{}/query", origin),
        base_url.to_string(),
    ]
}

async fn probe_graphql_endpoint(endpoint: &str, engine: &Engine) -> Option<GraphqlEndpointResult> {
    let client = &engine.client;

    // 1. Send Introspection Query (POST JSON)
    let intro_query = json!({
        "query": "{ __schema { types { name kind } } }"
    });

    let post_res = client
        .post(endpoint)
        .json(&intro_query)
        .timeout(Duration::from_secs(5))
        .send()
        .await
        .ok()?;

    let status_code = post_res.status().as_u16();
    let body_text = post_res.text().await.unwrap_or_default();

    // Verify if it's a GraphQL response
    let json_val: Value = serde_json::from_str(&body_text).ok()?;
    if json_val.get("data").is_none() && json_val.get("errors").is_none() {
        return None;
    }

    let mut introspection_enabled = false;
    let mut total_types_count = 0;
    let mut sample_types = Vec::new();

    if let Some(types) = json_val
        .get("data")
        .and_then(|d| d.get("__schema"))
        .and_then(|s| s.get("types"))
        .and_then(|t| t.as_array())
    {
        introspection_enabled = true;
        total_types_count = types.len();

        for t in types {
            if let Some(name) = t.get("name").and_then(|n| n.as_str()) {
                if !name.starts_with("__") {
                    sample_types.push(name.to_string());
                }
            }
        }
    }

    // 2. Probe for Field Suggestions with intentional typo
    let typo_query = json!({
        "query": "{ __schem }"
    });

    let mut field_suggestions = false;
    if let Ok(typo_res) = client
        .post(endpoint)
        .json(&typo_query)
        .timeout(Duration::from_secs(4))
        .send()
        .await
    {
        let typo_body = typo_res.text().await.unwrap_or_default();
        if typo_body.contains("Did you mean") || typo_body.contains("__schema") {
            field_suggestions = true;
        }
    }

    // 3. Probe GET Query Support
    let mut get_method_allowed = false;
    let get_url = format!("{}?query=%7B__typename%7D", endpoint);
    if let Ok(get_res) = client
        .get(&get_url)
        .timeout(Duration::from_secs(4))
        .send()
        .await
    {
        if get_res.status().is_success() {
            let get_body = get_res.text().await.unwrap_or_default();
            if get_body.contains("data") || get_body.contains("__typename") {
                get_method_allowed = true;
            }
        }
    }

    // 4. Probe for Interactive Playground / GraphiQL Web UI
    let mut playground_exposed = false;
    if let Ok(html_res) = client
        .get(endpoint)
        .header("Accept", "text/html")
        .timeout(Duration::from_secs(4))
        .send()
        .await
    {
        let html_body = html_res.text().await.unwrap_or_default();
        if html_body.contains("GraphQL Playground")
            || html_body.contains("GraphiQL")
            || html_body.contains("Apollo Server")
            || html_body.contains("Altair")
        {
            playground_exposed = true;
        }
    }

    Some(GraphqlEndpointResult {
        endpoint_url: endpoint.to_string(),
        status_code: Some(status_code),
        introspection_enabled,
        total_types_count,
        sample_types,
        field_suggestions,
        get_method_allowed,
        playground_exposed,
    })
}

fn format_report(target_url: &str, res: &GraphqlEndpointResult) -> String {
    let mut report = String::new();
    report.push_str("# SecLens API Security: GraphQL Security Audit\n\n");
    report.push_str(&format!("- **Target URL:** `{}`\n", target_url));
    report.push_str(&format!(
        "- **Active GraphQL Endpoint:** `{}`\n",
        res.endpoint_url
    ));
    report.push_str(&format!(
        "- **HTTP Status Code:** `{}`\n\n",
        res.status_code.unwrap_or(200)
    ));

    let (score, grade) = calculate_graphql_score(
        res.introspection_enabled,
        res.field_suggestions,
        res.get_method_allowed,
        res.playground_exposed,
    );

    report.push_str(&format!(
        "### GraphQL Hardening Score: **{} / 100** (Grade: **{}**)\n\n",
        score, grade
    ));

    report.push_str("| Security Metric | Status | Risk Assessment |\n");
    report.push_str("| :--- | :---: | :--- |\n");
    report.push_str(&format!(
        "| **Introspection Query** | {} | {} |\n",
        if res.introspection_enabled {
            "🚨 **ENABLED**"
        } else {
            "✅ Disabled"
        },
        if res.introspection_enabled {
            "CRITICAL: Full database & schema architecture exposed"
        } else {
            "Secure: Schema query rejected"
        }
    ));
    report.push_str(&format!(
        "| **Field Suggestions** | {} | {} |\n",
        if res.field_suggestions {
            "⚠️ **ENABLED**"
        } else {
            "✅ Disabled"
        },
        if res.field_suggestions {
            "MEDIUM: Leaks schema field names via 'Did you mean?'"
        } else {
            "Clean"
        }
    ));
    report.push_str(&format!(
        "| **GET Method Query Support** | {} | {} |\n",
        if res.get_method_allowed {
            "⚠️ Allowed"
        } else {
            "✅ Blocked"
        },
        if res.get_method_allowed {
            "MEDIUM: Potential CSRF and proxy cache poisoning risk"
        } else {
            "Strict POST enforcement"
        }
    ));
    report.push_str(&format!(
        "| **Playground / GraphiQL UI** | {} | {} |\n\n",
        if res.playground_exposed {
            "🚨 **EXPOSED**"
        } else {
            "✅ Hidden"
        },
        if res.playground_exposed {
            "HIGH: Interactive IDE console accessible to public"
        } else {
            "Clean"
        }
    ));

    if res.introspection_enabled {
        report.push_str("> [!CAUTION]\n");
        report.push_str("> **PUBLIC GRAPHQL INTROSPECTION VULNERABILITY!**\n");
        report.push_str("> The GraphQL endpoint returned the complete schema definition. An attacker can map all database models, internal entities, field types, and mutation signatures to construct automated exploits.\n\n");

        report.push_str(&format!(
            "### Schema Discovery Statistics\n- **Total Schema Types:** `{}`\n",
            res.total_types_count
        ));
        if !res.sample_types.is_empty() {
            let sample_slice = if res.sample_types.len() > 25 {
                &res.sample_types[..25]
            } else {
                &res.sample_types
            };
            report.push_str(&format!(
                "- **Sample Discovered User Types ({}):**\n",
                sample_slice.len()
            ));
            for t in sample_slice {
                report.push_str(&format!("  * `{}`\n", t));
            }
        }
        report.push('\n');
    }

    report.push_str("### Hardening & Remediation Guide\n");
    report.push_str("1. **Disable Introspection in Production:**\n");
    report.push_str("   - **Apollo Server:** Set `introspection: false` in `ApolloServer` constructor options.\n");
    report.push_str("   - **GraphQL Yoga / Envelop:** Add `@envelop/disable-introspection` plugin in production.\n");
    report.push_str("   - **Strawberry (Python):** Pass `introspection=False` to `Schema`.\n");
    report.push_str("2. **Disable Field Suggestions:** Suppress 'Did you mean' error enhancements to prevent schema brute-forcing.\n");
    report.push_str("3. **Disable Interactive IDEs in Production:** Ensure GraphiQL, Apollo Sandbox, and GraphQL Playground are conditionally disabled for production builds.\n");
    report.push_str("4. **Enforce POST Method Only:** Reject GET requests containing query payloads to prevent CSRF and unintended proxy caching.\n");

    report
}

fn calculate_graphql_score(
    intro: bool,
    suggestions: bool,
    get_allowed: bool,
    playground: bool,
) -> (u32, &'static str) {
    let mut score: u32 = 100;
    if intro {
        score = score.saturating_sub(45);
    }
    if playground {
        score = score.saturating_sub(25);
    }
    if suggestions {
        score = score.saturating_sub(15);
    }
    if get_allowed {
        score = score.saturating_sub(10);
    }

    let grade = match score {
        95..=100 => "A+",
        85..=94 => "A",
        70..=84 => "B",
        55..=69 => "C",
        40..=54 => "D",
        _ => "F",
    };

    (score, grade)
}
