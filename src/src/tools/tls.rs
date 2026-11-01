use chrono::{DateTime, Utc};
use rustls::client::danger::{HandshakeSignatureValid, ServerCertVerified, ServerCertVerifier};
use rustls::pki_types::{CertificateDer, ServerName, UnixTime};
use rustls::{ClientConfig, DigitallySignedStruct, Error, SignatureScheme};
use serde_json::Value;
use std::sync::{Arc, Mutex};
use std::time::Duration;
use tokio::net::TcpStream;
use tokio_rustls::TlsConnector;
use x509_parser::prelude::*;
use x509_parser::public_key::PublicKey;

#[derive(Debug)]
struct CertCollector {
    captured_chain: Arc<Mutex<Vec<Vec<u8>>>>,
}

impl ServerCertVerifier for CertCollector {
    fn verify_server_cert(
        &self,
        end_entity: &CertificateDer<'_>,
        intermediates: &[CertificateDer<'_>],
        _server_name: &ServerName<'_>,
        _ocsp_response: &[u8],
        _now: UnixTime,
    ) -> Result<ServerCertVerified, Error> {
        let mut chain = Vec::new();
        chain.push(end_entity.as_ref().to_vec());
        for intermediate in intermediates {
            chain.push(intermediate.as_ref().to_vec());
        }

        if let Ok(mut lock) = self.captured_chain.lock() {
            *lock = chain;
        }

        Ok(ServerCertVerified::assertion())
    }

    fn verify_tls12_signature(
        &self,
        _message: &[u8],
        _cert: &CertificateDer<'_>,
        _dss: &DigitallySignedStruct,
    ) -> Result<HandshakeSignatureValid, Error> {
        Ok(HandshakeSignatureValid::assertion())
    }

    fn verify_tls13_signature(
        &self,
        _message: &[u8],
        _cert: &CertificateDer<'_>,
        _dss: &DigitallySignedStruct,
    ) -> Result<HandshakeSignatureValid, Error> {
        Ok(HandshakeSignatureValid::assertion())
    }

    fn supported_verify_schemes(&self) -> Vec<SignatureScheme> {
        rustls::crypto::ring::default_provider()
            .signature_verification_algorithms
            .supported_schemes()
    }
}

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

    let port = args.get("port").and_then(|v| v.as_u64()).unwrap_or(443) as u16;

    let target_addr = format!("{}:{}", clean_domain, port);

    // 1. Configure Rustls with Certificate Collector
    let captured = Arc::new(Mutex::new(Vec::new()));
    let verifier = Arc::new(CertCollector {
        captured_chain: captured.clone(),
    });

    let config =
        ClientConfig::builder_with_provider(Arc::new(rustls::crypto::ring::default_provider()))
            .with_safe_default_protocol_versions()
            .map_err(|e| format!("Failed to configure TLS protocols: {}", e))?
            .dangerous()
            .with_custom_certificate_verifier(verifier)
            .with_no_client_auth();

    let connector = TlsConnector::from(Arc::new(config));

    // 2. Connect over TCP with 5s timeout
    let tcp_stream = tokio::time::timeout(Duration::from_secs(5), TcpStream::connect(&target_addr))
        .await
        .map_err(|_| format!("Connection timeout connecting to {}", target_addr))?
        .map_err(|e| format!("TCP connection failed to {}: {}", target_addr, e))?;

    let server_name = ServerName::try_from(clean_domain.to_string())
        .map_err(|e| format!("Invalid DNS name '{}': {}", clean_domain, e))?;

    // 3. Complete TLS Handshake
    let _tls_stream = tokio::time::timeout(
        Duration::from_secs(5),
        connector.connect(server_name, tcp_stream),
    )
    .await
    .map_err(|_| format!("TLS Handshake timeout with {}", clean_domain))?
    .map_err(|e| format!("TLS Handshake failed with {}: {}", clean_domain, e))?;

    // 4. Retrieve Captured Certificates
    let cert_chain = captured
        .lock()
        .map_err(|e| format!("Lock poisoned: {}", e))?
        .clone();

    if cert_chain.is_empty() {
        return Err("No certificates returned by the remote server during handshake".to_string());
    }

    let end_entity_der = &cert_chain[0];
    let (_, x509_cert) = parse_x509_certificate(end_entity_der)
        .map_err(|e| format!("Failed to parse X.509 certificate: {}", e))?;

    // 5. Extract Certificate Details
    let subject = x509_cert.subject().to_string();
    let issuer = x509_cert.issuer().to_string();

    let not_before_ts = x509_cert.validity().not_before.timestamp();
    let not_after_ts = x509_cert.validity().not_after.timestamp();
    let now_ts = Utc::now().timestamp();

    let not_before_dt = DateTime::from_timestamp(not_before_ts, 0)
        .map(|d| d.to_rfc3339())
        .unwrap_or_else(|| not_before_ts.to_string());
    let not_after_dt = DateTime::from_timestamp(not_after_ts, 0)
        .map(|d| d.to_rfc3339())
        .unwrap_or_else(|| not_after_ts.to_string());

    let days_remaining = (not_after_ts - now_ts) / 86400;

    // Extract SANs
    let mut sans = Vec::new();
    if let Ok(Some(ext)) = x509_cert.subject_alternative_name() {
        for name in &ext.value.general_names {
            if let GeneralName::DNSName(dns) = name {
                sans.push(dns.to_string());
            }
        }
    }

    // Public Key Info
    let pki = x509_cert.public_key();
    let (key_type, key_bits, is_key_strong) = match pki.parsed() {
        Ok(PublicKey::RSA(rsa)) => {
            let bits = rsa.modulus.len() * 8;
            ("RSA", bits, bits >= 2048)
        }
        Ok(PublicKey::EC(_)) => ("ECDSA", 256, true),
        Ok(PublicKey::DSA(_)) => ("DSA", 1024, false),
        Ok(PublicKey::GostR3410(_)) => ("GOST", 256, true),
        _ => ("Unknown", pki.raw.len() * 8, true),
    };

    // Signature Algorithm
    let sig_alg_oid = x509_cert.signature_algorithm.algorithm.to_string();
    let sig_alg_name = match sig_alg_oid.as_str() {
        "1.2.840.113549.1.1.11" => "SHA256withRSA",
        "1.2.840.113549.1.1.12" => "SHA384withRSA",
        "1.2.840.113549.1.1.13" => "SHA512withRSA",
        "1.2.840.10045.4.3.2" => "ECDSA-with-SHA256",
        "1.2.840.10045.4.3.3" => "ECDSA-with-SHA384",
        "1.2.840.113549.1.1.5" => "SHA1withRSA (Obsolete)",
        "1.2.840.113549.1.1.4" => "MD5withRSA (Broken)",
        _ => "Custom / Standard OID",
    };

    let is_weak_hash = sig_alg_oid == "1.2.840.113549.1.1.5"
        || sig_alg_oid == "1.2.840.113549.1.1.4"
        || sig_alg_name.contains("SHA1")
        || sig_alg_name.contains("MD5");

    // 6. Build Markdown Report
    let mut report = String::new();
    report.push_str("# SecLens TLS Certificate Audit\n");
    report.push_str(&format!("- **Target Host:** `{}`\n", target_addr));
    report.push_str(&format!(
        "- **Chain Depth:** `{}` certificates\n\n",
        cert_chain.len()
    ));

    report.push_str("### 1. Certificate Identity & Issuer\n");
    report.push_str("| Attribute | Value |\n");
    report.push_str("| :--- | :--- |\n");
    report.push_str(&format!("| `Subject` | `{}` |\n", subject));
    report.push_str(&format!("| `Issuer (CA)` | `{}` |\n", issuer));
    let sans_display = if sans.is_empty() {
        "None (Common Name only)".to_string()
    } else {
        sans.join(", ")
    };
    report.push_str(&format!(
        "| `Subject Alternative Names (SAN)` | `{}` |\n",
        sans_display
    ));

    report.push_str("\n### 2. Validity & Lifecycle Status\n");
    report.push_str("| Metric | Timestamp / Value | Security Status |\n");
    report.push_str("| :--- | :--- | :---: |\n");
    report.push_str(&format!(
        "| `Valid From (Not Before)` | `{}` | **ACTIVE** |\n",
        not_before_dt
    ));
    report.push_str(&format!("| `Valid To (Not After)` | `{}` | ", not_after_dt));

    if now_ts < not_before_ts {
        report.push_str("**FAIL** (Not yet valid) |\n");
    } else if now_ts > not_after_ts {
        report.push_str(&format!(
            "**CRITICAL** (Expired {} days ago) |\n",
            (now_ts - not_after_ts) / 86400
        ));
    } else if days_remaining < 30 {
        report.push_str(&format!(
            "**WARN** (Expiring in {} days! Immediate renewal required) |\n",
            days_remaining
        ));
    } else {
        report.push_str(&format!("**PASS** (Valid for {} days) |\n", days_remaining));
    }

    report.push_str("\n### 3. Cryptographic Strength\n");
    report.push_str("| Component | Specification | Security Verdict |\n");
    report.push_str("| :--- | :--- | :---: |\n");

    let key_verdict = if is_key_strong {
        "**PASS** (Industry Standard)"
    } else {
        "**FAIL** (Weak Key Length! Minimum 2048-bit RSA or 256-bit ECDSA required)"
    };
    report.push_str(&format!(
        "| `Public Key` | `{} ({} bits)` | {} |\n",
        key_type, key_bits, key_verdict
    ));

    let sig_verdict = if is_weak_hash {
        "**CRITICAL** (Deprecate immediately! Vulnerable to collision attacks)"
    } else {
        "**PASS** (Collision Resistant)"
    };
    report.push_str(&format!(
        "| `Signature Algorithm` | `{} ({})` | {} |\n",
        sig_alg_name, sig_alg_oid, sig_verdict
    ));

    Ok(report)
}
