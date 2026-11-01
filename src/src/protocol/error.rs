use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct JsonRpcError {
    pub code: i32,
    pub message: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub data: Option<serde_json::Value>,
}

#[allow(dead_code)]
impl JsonRpcError {
    pub fn parse_error(detail: &str) -> Self {
        Self {
            code: -32700,
            message: format!("Parse error: {}", detail),
            data: None,
        }
    }

    pub fn invalid_request(detail: &str) -> Self {
        Self {
            code: -32600,
            message: format!("Invalid Request: {}", detail),
            data: None,
        }
    }

    pub fn method_not_found(method: &str) -> Self {
        Self {
            code: -32601,
            message: format!("Method '{}' not found", method),
            data: None,
        }
    }

    pub fn invalid_params(detail: &str) -> Self {
        Self {
            code: -32602,
            message: format!("Invalid params: {}", detail),
            data: None,
        }
    }

    pub fn internal_error(detail: &str) -> Self {
        Self {
            code: -32603,
            message: format!("Internal error: {}", detail),
            data: None,
        }
    }
}
