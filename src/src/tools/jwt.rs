use base64::engine::general_purpose::{URL_SAFE, URL_SAFE_NO_PAD};
use base64::Engine;
use chrono::Utc;
use serde_json::Value;

const WEAK_SECRETS: &[&str] = &[
    "secret",
    "password",
    "123456",
    "12345678",
    "123456789",
    "admin",
    "jwt_secret",
    "development",
    "supersecret",
    "app_key",
    "key",
    "root",
    "test",
    "qwerty",
    "default",
    "private",
    "token",
    "master",
    "auth",
    "api_secret",
    "secret123",
    "pass123",
    "changeme",
    "welcome",
    "login",
    "service",
    "system",
    "guest",
    "demo",
    "database",
    "user",
    "access",
    "secure",
    "mysecret",
    "testing",
    "backend",
    "frontend",
    "production",
    "staging",
    "local",
    "session",
    "cookie",
    "signature",
    "hmac",
    "sha256",
    "jwt",
    "token123",
    "seclens",
    "internal",
    "security",
    "letmein",
];

pub async fn run(args: Value) -> Result<String, String> {
    let token_str = args
        .get("token")
        .and_then(|v| v.as_str())
        .ok_or_else(|| "Missing required parameter 'token'".to_string())?
        .trim();

    let parts: Vec<&str> = token_str.split('.').collect();
    if parts.len() < 2 {
        return Err(
            "Invalid JWT format: Expected 3 parts separated by dots (header.payload.signature)"
                .to_string(),
        );
    }

    // 1. Decode Header
    let header_bytes =
        decode_base64_url(parts[0]).map_err(|e| format!("Base64 header decode failed: {}", e))?;
    let header: Value = serde_json::from_slice(&header_bytes)
        .map_err(|e| format!("Invalid JSON in header: {}", e))?;

    // 2. Decode Payload
    let payload_bytes =
        decode_base64_url(parts[1]).map_err(|e| format!("Base64 payload decode failed: {}", e))?;
    let payload: Value = serde_json::from_slice(&payload_bytes)
        .map_err(|e| format!("Invalid JSON in payload: {}", e))?;

    // 3. Signature bytes (if present)
    let signature_bytes = if parts.len() >= 3 && !parts[2].is_empty() {
        decode_base64_url(parts[2]).ok()
    } else {
        None
    };

    let mut report = String::new();
    report.push_str("# SecLens JWT Cryptographic & Structure Analysis\n\n");

    // Section 1: Header Breakdown
    report.push_str("### 1. Token Header\n");
    report.push_str("| Header Key | Value | Description |\n");
    report.push_str("| :--- | :--- | :--- |\n");
    if let Some(obj) = header.as_object() {
        for (k, v) in obj {
            let desc = match k.as_str() {
                "alg" => "Cryptographic signing algorithm",
                "typ" => "Token type (typically JWT)",
                "kid" => "Key Identifier for public key lookups",
                "jku" => "JWK Set URL (potential SSRF vector)",
                "x5u" => "X.509 URL",
                "cty" => "Content Type",
                _ => "Custom header parameter",
            };
            report.push_str(&format!("| `{}` | `{}` | {} |\n", k, v, desc));
        }
    }

    // Section 2: Payload Claims Breakdown
    report.push_str("\n### 2. Token Payload (Claims)\n");
    report.push_str("| Claim Key | Value | Standard Definition |\n");
    report.push_str("| :--- | :--- | :--- |\n");
    if let Some(obj) = payload.as_object() {
        for (k, v) in obj {
            let desc = match k.as_str() {
                "sub" => "Subject (User identifier)",
                "iss" => "Issuer (Authority that created the token)",
                "aud" => "Audience (Intended recipients)",
                "exp" => "Expiration timestamp (Unix epoch)",
                "nbf" => "Not Before timestamp (Token cannot be used prior)",
                "iat" => "Issued At timestamp (Token creation time)",
                "jti" => "JWT ID (Unique token nonce)",
                "role" | "roles" => "Authorization roles",
                "email" => "User email address",
                _ => "Application claim",
            };
            let val_str = serde_json::to_string(v).unwrap_or_else(|_| v.to_string());
            report.push_str(&format!("| `{}` | `{}` | {} |\n", k, val_str, desc));
        }
    }

    // Section 3: Security & Cryptographic Risk Findings
    report.push_str("\n### 3. Security Findings & Risk Verdicts\n");
    report.push_str("| Vulnerability Check | Severity | Technical Assessment & Remediation |\n");
    report.push_str("| :--- | :---: | :--- |\n");

    let alg_raw = header.get("alg").and_then(|v| v.as_str()).unwrap_or("none");
    let alg_lower = alg_raw.to_lowercase();

    // Check A: Algorithm none
    if alg_lower == "none" {
        report.push_str("| `Algorithm 'none'` | **CRITICAL** | Token specifies `alg: none`. Signatures are skipped; attackers can forge arbitrary claims. |\n");
    } else {
        report.push_str(&format!(
            "| `Algorithm` | **PASS** | Token uses `{}` signature algorithm. |\n",
            alg_raw
        ));
    }

    // Check B: Weak HMAC Key Dictionary Attack (HS256)
    if alg_lower == "hs256" {
        if let Some(sig) = &signature_bytes {
            let signing_input = format!("{}.{}", parts[0], parts[1]);
            let mut cracked_secret = None;

            for &weak_candidate in WEAK_SECRETS {
                let key = ring::hmac::Key::new(ring::hmac::HMAC_SHA256, weak_candidate.as_bytes());
                if ring::hmac::verify(&key, signing_input.as_bytes(), sig).is_ok() {
                    cracked_secret = Some(weak_candidate);
                    break;
                }
            }

            if let Some(secret) = cracked_secret {
                report.push_str(&format!(
                    "| `Weak HMAC Secret` | **CRITICAL** | Signature verified with common dictionary password: `{}`! Attackers can forge administrative tokens. |\n",
                    secret
                ));
            } else {
                report.push_str("| `Weak HMAC Secret` | **PASS** | Offline dictionary test against 50 top default secrets passed. |\n");
            }
        } else {
            report.push_str("| `Missing Signature` | **CRITICAL** | Token specifies HS256 but lacks signature bytes. |\n");
        }
    }

    // Check C: Timestamps Validation (exp, nbf, iat)
    let now = Utc::now().timestamp();

    if let Some(exp) = payload.get("exp").and_then(|v| v.as_i64()) {
        if exp < now {
            let diff = now - exp;
            report.push_str(&format!(
                "| `Expiration (exp)` | **WARN** | Token expired at unix `{}` ({} seconds / {:.1} hours ago). |\n",
                exp, diff, diff as f64 / 3600.0
            ));
        } else {
            let remaining = exp - now;
            report.push_str(&format!(
                "| `Expiration (exp)` | **PASS** | Token is valid (expires in {} seconds / {:.1} hours). |\n",
                remaining, remaining as f64 / 3600.0
            ));
        }
    } else {
        report.push_str("| `Expiration (exp)` | **WARN** | Token has no `exp` claim. Perpetual tokens cannot be revoked if compromised. |\n");
    }

    if let Some(nbf) = payload.get("nbf").and_then(|v| v.as_i64()) {
        if nbf > now {
            let until = nbf - now;
            report.push_str(&format!(
                "| `Not Before (nbf)` | **WARN** | Token is premature! Valid only starting in {} seconds. |\n",
                until
            ));
        } else {
            report.push_str("| `Not Before (nbf)` | **PASS** | Token is active and past its `nbf` threshold. |\n");
        }
    }

    if let Some(iat) = payload.get("iat").and_then(|v| v.as_i64()) {
        if iat > now + 120 {
            report.push_str(&format!(
                "| `Issued At (iat)` | **WARN** | Token was issued in the future (skew: {}s). Check clock sync. |\n",
                iat - now
            ));
        }
    }

    // Check D: Sensitive Leaked Data in Claims
    let sensitive_keys = [
        "password",
        "pass",
        "passwd",
        "hash",
        "secret",
        "private_key",
        "token",
        "ssn",
        "credit_card",
        "pin",
        "auth_key",
    ];

    let mut leaked = Vec::new();
    if let Some(obj) = payload.as_object() {
        for key in obj.keys() {
            let lower_k = key.to_lowercase();
            for s in sensitive_keys {
                if lower_k.contains(s) {
                    leaked.push(key.clone());
                    break;
                }
            }
        }
    }

    if !leaked.is_empty() {
        report.push_str(&format!(
            "| `Data Exposure` | **HIGH RISK** | Found sensitive field names in client-visible claims: `{:?}`. Never store passwords, hashes or private keys in JWTs. |\n",
            leaked
        ));
    } else {
        report.push_str("| `Data Exposure` | **PASS** | No blatantly sensitive field names detected in claims. |\n");
    }

    Ok(report)
}

fn decode_base64_url(input: &str) -> Result<Vec<u8>, String> {
    if let Ok(bytes) = URL_SAFE_NO_PAD.decode(input) {
        return Ok(bytes);
    }
    if let Ok(bytes) = URL_SAFE.decode(input) {
        return Ok(bytes);
    }
    let missing_padding = (4 - (input.len() % 4)) % 4;
    let padded = format!("{}{}", input, "=".repeat(missing_padding));
    URL_SAFE.decode(&padded).map_err(|e| e.to_string())
}
