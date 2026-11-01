mod engine;
mod protocol;
mod tools;

use engine::Engine;
use protocol::{JsonRpcError, JsonRpcRequest, JsonRpcResponse};
use serde_json::json;
use std::io::{self, BufRead, Write};
use tracing::{error, info};

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    // Log exclusively to stderr so JSON-RPC on stdout remains clean
    tracing_subscriber::fmt()
        .with_writer(io::stderr)
        .with_env_filter(
            tracing_subscriber::EnvFilter::from_default_env()
                .add_directive(tracing::Level::INFO.into()),
        )
        .init();

    info!("SecLens-MCP server starting on stdio transport...");

    let engine = Engine::new()?;
    let stdin = io::stdin();
    let stdout = io::stdout();
    let mut stdout_lock = stdout.lock();

    for line in stdin.lock().lines() {
        let line = match line {
            Ok(l) => l,
            Err(e) => {
                error!("Failed to read line from stdin: {}", e);
                break;
            }
        };

        let trimmed = line.trim();
        if trimmed.is_empty() {
            continue;
        }

        let request: JsonRpcRequest = match serde_json::from_str(trimmed) {
            Ok(req) => req,
            Err(e) => {
                error!("Invalid JSON-RPC frame: {}", e);
                let err_resp =
                    JsonRpcResponse::err(None, JsonRpcError::parse_error(&e.to_string()));
                send_response(&mut stdout_lock, &err_resp)?;
                continue;
            }
        };

        // Notifications (id is None) that don't need a response
        if request.id.is_none() && request.method.starts_with("notifications/") {
            info!("Received notification: {}", request.method);
            continue;
        }

        let response = handle_request(request, &engine).await;
        send_response(&mut stdout_lock, &response)?;
    }

    info!("SecLens-MCP server terminated.");
    Ok(())
}

async fn handle_request(req: JsonRpcRequest, engine: &Engine) -> JsonRpcResponse {
    match req.method.as_str() {
        "initialize" => {
            let result = json!({
                "protocolVersion": "2024-11-05",
                "capabilities": {
                    "tools": {}
                },
                "serverInfo": {
                    "name": "seclens-mcp",
                    "version": "1.0.0"
                }
            });
            JsonRpcResponse::success(req.id, result)
        }

        "tools/list" => {
            let tools = tools::list_tools();
            JsonRpcResponse::success(req.id, json!({ "tools": tools }))
        }

        "tools/call" => {
            let params = match req.params {
                Some(p) => p,
                None => {
                    return JsonRpcResponse::err(
                        req.id,
                        JsonRpcError::invalid_params("Missing params object"),
                    );
                }
            };

            let tool_name = match params.get("name").and_then(|v| v.as_str()) {
                Some(n) => n,
                None => {
                    return JsonRpcResponse::err(
                        req.id,
                        JsonRpcError::invalid_params("Missing tool 'name' field in params"),
                    );
                }
            };

            let args = params.get("arguments").cloned().unwrap_or(json!({}));
            info!("Calling tool: {}", tool_name);

            let tool_result = tools::dispatch_tool(tool_name, args, engine).await;
            JsonRpcResponse::success(req.id, json!(tool_result))
        }

        "ping" => JsonRpcResponse::success(req.id, json!({})),

        other => JsonRpcResponse::err(req.id, JsonRpcError::method_not_found(other)),
    }
}

fn send_response(writer: &mut impl Write, resp: &JsonRpcResponse) -> io::Result<()> {
    let serialized = serde_json::to_string(resp)?;
    writeln!(writer, "{}", serialized)?;
    writer.flush()?;
    Ok(())
}
