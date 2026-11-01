pub mod cors;
pub mod dns_email;
pub mod dns_resilience;
pub mod files;
pub mod headers;
pub mod jwt;
pub mod openapi;
pub mod report;
pub mod secrets;
pub mod tls;

use crate::engine::Engine;
use crate::protocol::{ToolCallResult, ToolDefinition};
use serde_json::{json, Value};

pub fn list_tools() -> Vec<ToolDefinition> {
    vec![
        ToolDefinition {
            name: "check_security_headers".to_string(),
            description: "Scans and evaluates HTTP security defense headers (CSP, HSTS, X-Frame-Options, X-Content-Type, Referrer-Policy, Server info leaks) for a target URL.".to_string(),
            input_schema: json!({
                "type": "object",
                "properties": {
                    "url": {
                        "type": "string",
                        "description": "Target website or API URL (e.g. https://example.com)"
                    }
                },
                "required": ["url"]
            }),
        },
        ToolDefinition {
            name: "detect_exposed_files".to_string(),
            description: "Audits a website for accidentally leaked sensitive files (.env, .git/HEAD, backup.sql, docker-compose.yml, private keys, database dumps).".to_string(),
            input_schema: json!({
                "type": "object",
                "properties": {
                    "url": {
                        "type": "string",
                        "description": "Base URL of the target web server (e.g. https://example.com)"
                    }
                },
                "required": ["url"]
            }),
        },
        ToolDefinition {
            name: "audit_cors_policy".to_string(),
            description: "Tests Cross-Origin Resource Sharing (CORS) policy for misconfigurations, arbitrary origin reflection, and credential leakage.".to_string(),
            input_schema: json!({
                "type": "object",
                "properties": {
                    "url": {
                        "type": "string",
                        "description": "Target API endpoint URL to probe for CORS behavior"
                    }
                },
                "required": ["url"]
            }),
        },
        ToolDefinition {
            name: "analyze_jwt_token".to_string(),
            description: "Inspects and decodes a JSON Web Token (JWT) offline for algorithm 'none' flaws, weak signature dictionary keys, expiration, and sensitive claims leaks.".to_string(),
            input_schema: json!({
                "type": "object",
                "properties": {
                    "token": {
                        "type": "string",
                        "description": "Raw JWT token string (header.payload.signature)"
                    }
                },
                "required": ["token"]
            }),
        },
        ToolDefinition {
            name: "inspect_tls_certificate".to_string(),
            description: "Inspects remote server SSL/TLS X.509 certificate chain, Subject Alternative Names (SANs), CA issuer, expiration lifecycle, and cryptographic key strength.".to_string(),
            input_schema: json!({
                "type": "object",
                "properties": {
                    "domain": {
                        "type": "string",
                        "description": "Target server domain or hostname (e.g. example.com)"
                    },
                    "port": {
                        "type": "integer",
                        "description": "Port number (default 443)",
                        "default": 443
                    }
                },
                "required": ["domain"]
            }),
        },
        ToolDefinition {
            name: "audit_openapi_spec".to_string(),
            description: "Audits OpenAPI / Swagger 2.0 / 3.0 API definitions for unauthenticated endpoints, exposed admin/debug routes, and unprotected destructive HTTP methods.".to_string(),
            input_schema: json!({
                "type": "object",
                "properties": {
                    "url": {
                        "type": "string",
                        "description": "URL pointing to openapi.json or swagger.json file (e.g. https://example.com/openapi.json)"
                    }
                },
                "required": ["url"]
            }),
        },
        ToolDefinition {
            name: "check_email_security".to_string(),
            description: "Evaluates domain email defense mechanisms (SPF mechanism validity, DMARC policy enforcement, and DKIM selector keys) for anti-spoofing resilience.".to_string(),
            input_schema: json!({
                "type": "object",
                "properties": {
                    "domain": {
                        "type": "string",
                        "description": "Domain name to audit (e.g. example.com)"
                    }
                },
                "required": ["domain"]
            }),
        },
        ToolDefinition {
            name: "check_dns_resilience".to_string(),
            description: "Audits domain DNS infrastructure resilience, CAA certificate issuance restrictions, DNSSEC cryptographic signing, and dangling CNAME takeover vulnerabilities.".to_string(),
            input_schema: json!({
                "type": "object",
                "properties": {
                    "domain": {
                        "type": "string",
                        "description": "Domain name to audit (e.g. example.com)"
                    }
                },
                "required": ["domain"]
            }),
        },
        ToolDefinition {
            name: "scan_hardcoded_secrets".to_string(),
            description: "Scans local codebase directory for hardcoded API keys, Telegram tokens, AWS secrets, database URIs, private keys, and high-entropy strings using Shannon entropy.".to_string(),
            input_schema: json!({
                "type": "object",
                "properties": {
                    "path": {
                        "type": "string",
                        "description": "Local folder path to audit (defaults to current directory '.')",
                        "default": "."
                    }
                }
            }),
        },
        ToolDefinition {
            name: "generate_security_report".to_string(),
            description: "Executes an orchestrated, comprehensive perimeter security assessment across headers, files, CORS, DNS, email spoofing, and TLS, compiling an executive posture report with OWASP/CWE mappings and remediation roadmap.".to_string(),
            input_schema: json!({
                "type": "object",
                "properties": {
                    "target": {
                        "type": "string",
                        "description": "Target website URL or domain name (e.g. https://example.com or example.com)"
                    },
                    "include_raw_data": {
                        "type": "boolean",
                        "description": "Whether to append all detailed raw sub-module markdown audit tables to the executive report (default: false)",
                        "default": false
                    }
                },
                "required": ["target"]
            }),
        },
    ]
}

pub async fn dispatch_tool(name: &str, args: Value, engine: &Engine) -> ToolCallResult {
    match name {
        "check_security_headers" => match headers::run(args, engine).await {
            Ok(output) => ToolCallResult::text(output),
            Err(e) => ToolCallResult::error(e),
        },
        "detect_exposed_files" => match files::run(args, engine).await {
            Ok(output) => ToolCallResult::text(output),
            Err(e) => ToolCallResult::error(e),
        },
        "audit_cors_policy" => match cors::run(args, engine).await {
            Ok(output) => ToolCallResult::text(output),
            Err(e) => ToolCallResult::error(e),
        },
        "analyze_jwt_token" => match jwt::run(args).await {
            Ok(output) => ToolCallResult::text(output),
            Err(e) => ToolCallResult::error(e),
        },
        "inspect_tls_certificate" => match tls::run(args).await {
            Ok(output) => ToolCallResult::text(output),
            Err(e) => ToolCallResult::error(e),
        },
        "audit_openapi_spec" => match openapi::run(args, engine).await {
            Ok(output) => ToolCallResult::text(output),
            Err(e) => ToolCallResult::error(e),
        },
        "check_email_security" => match dns_email::run(args).await {
            Ok(output) => ToolCallResult::text(output),
            Err(e) => ToolCallResult::error(e),
        },
        "check_dns_resilience" => match dns_resilience::run(args).await {
            Ok(output) => ToolCallResult::text(output),
            Err(e) => ToolCallResult::error(e),
        },
        "scan_hardcoded_secrets" => match secrets::run(args).await {
            Ok(output) => ToolCallResult::text(output),
            Err(e) => ToolCallResult::error(e),
        },
        "generate_security_report" => match report::run(args, engine).await {
            Ok(output) => ToolCallResult::text(output),
            Err(e) => ToolCallResult::error(e),
        },
        _ => ToolCallResult::error(format!("Tool '{}' is not registered on this server", name)),
    }
}
