# 🛡️ SecLens-MCP

**High-Performance, Async Security Auditing & Web Reconnaissance MCP Server written in Rust 🦀**

[English](#english) | [فارسی](#فارسی)

---

## English

`SecLens-MCP` is an ultra-fast Model Context Protocol (MCP) server engineered in pure Rust. It transforms your AI coding agent (Claude Code, Cursor, Zed, Hermes, Windsurf) into an autonomous application security (AppSec) auditor.

### Features & Tools
* `check_security_headers`: Evaluates CSP, HSTS, X-Frame-Options, MIME sniffing, and server info leaks.
* `detect_exposed_files`: Concurrently detects exposed `.git/HEAD`, `.env`, SQL dumps, and sensitive configuration files.
* `audit_cors_policy`: Discovers dangerous Cross-Origin Resource Sharing reflections and credential leaks.
* `analyze_jwt_token`: Offline cryptographic inspection of JWTs (detects `alg: none`, weak secrets, and claim leaks).
* `scan_hardcoded_secrets`: High-speed local regex engine identifying leaked Telegram bot tokens, OpenAI API keys, AWS keys, and private certificates.

### How to Build & Run Locally
```bash
# Clone and enter directory
git clone https://github.com/thetuxify/seclens-mcp.git
cd seclens-mcp/src

# Build release binary (optimized with LTO)
cargo build --release

# The compiled binary will be located at:
./target/release/seclens-mcp
```

### Adding to MCP Clients

#### 1. Claude Desktop / Claude Code
Add to `claude_desktop_config.json`:
```json
{
  "mcpServers": {
    "seclens": {
      "command": "/path/to/seclens-mcp/target/release/seclens-mcp"
    }
  }
}
```

#### 2. Hermes Agent
```bash
hermes mcp add seclens --command /path/to/seclens-mcp/target/release/seclens-mcp
```

---

## فارسی

`SecLens-MCP` یک سرور فوق‌سریع بر پایه پروتکل استاندارد MCP است که با زبان قدرتمند Rust توسعه یافته است. این ابزار به ایجنت‌های هوش مصنوعی امکان ممیزی امنیتی، اسکن سطح حمله و کشف آسیب‌پذیری‌های وب را در کسری از ثانیه می‌دهد.

### ابزارهای فعال در نسخه جاری:
۱. `check_security_headers`: بررسی جامع هدرهای دفاعی وب و ریسک‌های OWASP.
۲. `detect_exposed_files`: اسکن ناهمگام و موازی برای کشف فایل‌های نشت‌کرده نظیر `.env` و `.git`.
۳. `audit_cors_policy`: کشف خطاهای خطرناک در پیکربندی سیاست‌های اشتراک منابع مبدا (CORS).
۴. `analyze_jwt_token`: کالبدشکافی و تحلیل آفلاین توکن‌های JWT و بررسی الگوریتم‌ها و کلیدهای ضعیف.
۵. `scan_hardcoded_secrets`: پویش سریع سورس‌کد محلی برای پیدا کردن توکن‌ها و کلیدهای خصوصی قبل از کامیت.

### نحوه اجرا در سیستم:
```bash
cd seclens-mcp/src
cargo run --release
```

---
*Created by [Tuxify](https://t.me/thetuxify) — Built for high-assurance cybersecurity automation.*
