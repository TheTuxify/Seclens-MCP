use serde_json::{json, Value};
use std::fs;
use std::path::{Path, PathBuf};
use std::process::Command;

/// Tracks configuration status across AI developer environments
#[derive(Debug, Default)]
pub struct SetupSummary {
    pub antigravity: bool,
    pub claude: bool,
    pub zed: bool,
    pub cursor: bool,
    pub hermes: bool,
}

/// Executes auto-detection and registration across all supported AI assistants
pub fn run_setup() -> Result<(), Box<dyn std::error::Error>> {
    println!("\x1b[38;2;255;215;0m=== SecLens-MCP Auto-Setup Engine (v1.0.1) ===\x1b[0m\n");
    println!("Scanning system for installed AI developer environments...\n");

    let home = home_dir();
    let mut summary = SetupSummary::default();

    if let Some(ref home_path) = home {
        // 1. Google Antigravity (~/.gemini/antigravity-cli/settings.json)
        match setup_antigravity(home_path) {
            Ok(configured) => {
                if configured {
                    println!("\x1b[32m[✓]\x1b[0m Google Antigravity: Configured in ~/.gemini/antigravity-cli/settings.json");
                    summary.antigravity = true;
                } else {
                    println!("\x1b[90m[-]\x1b[0m Google Antigravity: Already up-to-date");
                    summary.antigravity = true;
                }
            }
            Err(e) => eprintln!("\x1b[31m[!]\x1b[0m Google Antigravity error: {}", e),
        }

        // 2. Claude Desktop (Linux, macOS, Windows)
        match setup_claude(home_path) {
            Ok(Some(path)) => {
                println!(
                    "\x1b[32m[✓]\x1b[0m Claude Desktop: Configured in {}",
                    path.display()
                );
                summary.claude = true;
            }
            Ok(None) => {
                println!("\x1b[90m[-]\x1b[0m Claude Desktop: Directory not found (skipped)");
            }
            Err(e) => eprintln!("\x1b[31m[!]\x1b[0m Claude Desktop error: {}", e),
        }

        // 3. Zed Editor (~/.config/zed/settings.json)
        match setup_zed(home_path) {
            Ok(Some(path)) => {
                println!(
                    "\x1b[32m[✓]\x1b[0m Zed Editor: Configured in {}",
                    path.display()
                );
                summary.zed = true;
            }
            Ok(None) => {
                println!("\x1b[90m[-]\x1b[0m Zed Editor: Directory not found (skipped)");
            }
            Err(e) => eprintln!("\x1b[31m[!]\x1b[0m Zed Editor error: {}", e),
        }

        // 4. Cursor IDE (mcp.json)
        match setup_cursor(home_path) {
            Ok(Some(path)) => {
                println!(
                    "\x1b[32m[✓]\x1b[0m Cursor IDE: Configured in {}",
                    path.display()
                );
                summary.cursor = true;
            }
            Ok(None) => {
                println!("\x1b[90m[-]\x1b[0m Cursor IDE: Directory not found (skipped)");
            }
            Err(e) => eprintln!("\x1b[31m[!]\x1b[0m Cursor IDE error: {}", e),
        }
    } else {
        eprintln!("\x1b[33m[!]\x1b[0m Unable to determine user home directory.");
    }

    // 5. Hermes Agent (hermes CLI)
    match setup_hermes() {
        Ok(true) => {
            println!("\x1b[32m[✓]\x1b[0m Hermes Agent: Registered via `hermes mcp add seclens`");
            summary.hermes = true;
        }
        Ok(false) => {
            println!("\x1b[90m[-]\x1b[0m Hermes Agent: CLI not found in PATH (skipped)");
        }
        Err(e) => eprintln!("\x1b[31m[!]\x1b[0m Hermes Agent error: {}", e),
    }

    let count = [
        summary.antigravity,
        summary.claude,
        summary.zed,
        summary.cursor,
        summary.hermes,
    ]
    .iter()
    .filter(|&&b| b)
    .count();

    println!("\n\x1b[38;2;255;215;0m--------------------------------------------------\x1b[0m");
    println!(
        "\x1b[32m[✓] Auto-setup complete! Successfully configured for {} client(s).\x1b[0m",
        count
    );
    println!("Restart your configured assistants to begin using SecLens-MCP security tools.\n");

    Ok(())
}

/// Resolves user home directory with sudo-safety
fn home_dir() -> Option<PathBuf> {
    if let Ok(sudo_user) = std::env::var("SUDO_USER") {
        if !sudo_user.trim().is_empty() && sudo_user != "root" {
            let user_home = PathBuf::from(format!("/home/{}", sudo_user));
            if user_home.exists() {
                return Some(user_home);
            }
        }
    }
    if let Ok(home) = std::env::var("HOME") {
        if !home.trim().is_empty() {
            return Some(PathBuf::from(home));
        }
    }
    if let Ok(userprofile) = std::env::var("USERPROFILE") {
        if !userprofile.trim().is_empty() {
            return Some(PathBuf::from(userprofile));
        }
    }
    None
}

/// Strip standard single-line (//) and block (/* */) comments from JSONC
fn strip_json_comments(input: &str) -> String {
    let mut out = String::with_capacity(input.len());
    let mut in_string = false;
    let mut escape = false;
    let mut chars = input.chars().peekable();

    while let Some(c) = chars.next() {
        if escape {
            out.push(c);
            escape = false;
            continue;
        }

        if c == '\\' && in_string {
            escape = true;
            out.push(c);
            continue;
        }

        if c == '"' {
            in_string = !in_string;
            out.push(c);
            continue;
        }

        if !in_string && c == '/' {
            if let Some(&'/') = chars.peek() {
                chars.next();
                for next_c in chars.by_ref() {
                    if next_c == '\n' {
                        out.push('\n');
                        break;
                    }
                }
                continue;
            } else if let Some(&'*') = chars.peek() {
                chars.next();
                while let Some(next_c) = chars.next() {
                    if next_c == '*' && chars.peek() == Some(&'/') {
                        chars.next();
                        break;
                    }
                }
                continue;
            }
        }

        out.push(c);
    }
    out
}

/// Reads, modifies, and writes back a JSON configuration file safely
fn update_json_file<F>(path: &Path, update_fn: F) -> Result<bool, Box<dyn std::error::Error>>
where
    F: FnOnce(&mut Value) -> bool,
{
    let mut root = if path.exists() {
        let content = fs::read_to_string(path)?;
        let trimmed = content.trim_start_matches('\u{feff}').trim();
        if trimmed.is_empty() {
            json!({})
        } else {
            match serde_json::from_str::<Value>(trimmed) {
                Ok(v) => v,
                Err(_) => {
                    let sanitized = strip_json_comments(trimmed);
                    serde_json::from_str::<Value>(&sanitized).unwrap_or_else(|_| json!({}))
                }
            }
        }
    } else {
        json!({})
    };

    if !root.is_object() {
        root = json!({});
    }

    let changed = update_fn(&mut root);

    if let Some(parent) = path.parent() {
        fs::create_dir_all(parent)?;
    }

    let formatted = serde_json::to_string_pretty(&root)?;
    fs::write(path, formatted + "\n")?;

    Ok(changed)
}

/// Configures Google Antigravity (~/.gemini/antigravity-cli/settings.json)
fn setup_antigravity(home: &Path) -> Result<bool, Box<dyn std::error::Error>> {
    let settings_path = home
        .join(".gemini")
        .join("antigravity-cli")
        .join("settings.json");

    update_json_file(&settings_path, |root| {
        if !root.get("mcpServers").is_some_and(|v| v.is_object()) {
            root["mcpServers"] = json!({});
        }

        let seclens_config = json!({
            "command": "seclens-mcp",
            "args": [],
            "disabled": false,
            "alwaysAllow": [
                "check_security_headers",
                "detect_exposed_files",
                "audit_cors_policy",
                "analyze_jwt_token",
                "inspect_tls_certificate",
                "audit_openapi_spec",
                "check_email_security",
                "check_dns_resilience",
                "scan_hardcoded_secrets",
                "generate_security_report"
            ]
        });

        root["mcpServers"]["seclens"] = seclens_config;
        true
    })
}

/// Configures Claude Desktop on Linux, macOS, or Windows
fn setup_claude(home: &Path) -> Result<Option<PathBuf>, Box<dyn std::error::Error>> {
    let candidates = [
        // Linux
        home.join(".config")
            .join("Claude")
            .join("claude_desktop_config.json"),
        home.join(".config")
            .join("claude")
            .join("claude_desktop_config.json"),
        // macOS
        home.join("Library")
            .join("Application Support")
            .join("Claude")
            .join("claude_desktop_config.json"),
        // Windows (AppData/Roaming/Claude)
        home.join("AppData")
            .join("Roaming")
            .join("Claude")
            .join("claude_desktop_config.json"),
    ];

    for candidate in &candidates {
        if candidate.exists() || candidate.parent().is_some_and(|p| p.exists() && p.is_dir()) {
            update_json_file(candidate, |root| {
                if !root.get("mcpServers").is_some_and(|v| v.is_object()) {
                    root["mcpServers"] = json!({});
                }
                root["mcpServers"]["seclens"] = json!({
                    "command": "seclens-mcp",
                    "args": [],
                    "env": {
                        "RUST_LOG": "info"
                    }
                });
                true
            })?;
            return Ok(Some(candidate.clone()));
        }
    }

    Ok(None)
}

/// Configures Zed Editor (~/.config/zed/settings.json)
fn setup_zed(home: &Path) -> Result<Option<PathBuf>, Box<dyn std::error::Error>> {
    let candidates = [
        home.join(".config").join("zed").join("settings.json"),
        home.join("Library")
            .join("Application Support")
            .join("Zed")
            .join("settings.json"),
    ];

    for candidate in &candidates {
        if candidate.exists() || candidate.parent().is_some_and(|p| p.exists() && p.is_dir()) {
            update_json_file(candidate, |root| {
                // Zed uses context_servers for MCP
                if !root.get("context_servers").is_some_and(|v| v.is_object()) {
                    root["context_servers"] = json!({});
                }
                root["context_servers"]["seclens"] = json!({
                    "command": {
                        "path": "seclens-mcp",
                        "args": []
                    }
                });
                true
            })?;
            return Ok(Some(candidate.clone()));
        }
    }

    Ok(None)
}

/// Configures Cursor IDE if configuration directory exists
fn setup_cursor(home: &Path) -> Result<Option<PathBuf>, Box<dyn std::error::Error>> {
    let candidates = [
        // ~/.cursor/mcp.json
        home.join(".cursor").join("mcp.json"),
        // ~/.config/Cursor/mcp.json
        home.join(".config").join("Cursor").join("mcp.json"),
        // macOS
        home.join("Library")
            .join("Application Support")
            .join("Cursor")
            .join("User")
            .join("mcp.json"),
        // Windows
        home.join("AppData")
            .join("Roaming")
            .join("Cursor")
            .join("User")
            .join("mcp.json"),
        // Local directory if .cursor exists
        PathBuf::from(".cursor").join("mcp.json"),
    ];

    for candidate in &candidates {
        if candidate.exists() || candidate.parent().is_some_and(|p| p.exists() && p.is_dir()) {
            update_json_file(candidate, |root| {
                if !root.get("mcpServers").is_some_and(|v| v.is_object()) {
                    root["mcpServers"] = json!({});
                }
                root["mcpServers"]["seclens"] = json!({
                    "command": "seclens-mcp",
                    "args": []
                });
                true
            })?;
            return Ok(Some(candidate.clone()));
        }
    }

    Ok(None)
}

/// Registers SecLens with Hermes Agent if `hermes` CLI is installed
fn setup_hermes() -> Result<bool, Box<dyn std::error::Error>> {
    match Command::new("hermes").arg("--version").output() {
        Ok(_) => {
            let output = Command::new("hermes")
                .args(["mcp", "add", "seclens", "--command", "seclens-mcp"])
                .output()?;
            if output.status.success() {
                Ok(true)
            } else {
                let err_msg = String::from_utf8_lossy(&output.stderr);
                // If it was already added or had message, check if success-like
                if err_msg.contains("already exists") {
                    Ok(true)
                } else {
                    Err(format!("Hermes CLI command failed: {}", err_msg.trim()).into())
                }
            }
        }
        Err(ref e) if e.kind() == std::io::ErrorKind::NotFound => Ok(false),
        Err(e) => Err(e.into()),
    }
}
