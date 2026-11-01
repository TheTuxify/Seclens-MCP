# SecLens-MCP (Rust Edition)
### High-Performance, Async Security Auditing & Reconnaissance Engine
#### موتور پیشرفته، فوق‌سریع و ناهمگام ممیزی و ارزیابی امنیتی پروتکل MCP به زبان رستم

[![Rust](https://img.shields.io/badge/Rust-1.75+-black.svg?style=flat&logo=rust)](https://www.rust-lang.org)
[![MCP](https://img.shields.io/badge/MCP-Protocol%202024--11--05-blue.svg)](https://modelcontextprotocol.io)
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](https://opensource.org/licenses/MIT)
[![Cross-Platform](https://img.shields.io/badge/Platform-Linux%20%7C%20macOS%20%7C%20Windows-green.svg)](#installation)

---

## 🌟 Overview | معرفی کلی

**SecLens-MCP** is an ultra-fast, lightweight, pure-Rust [Model Context Protocol (MCP)](https://modelcontextprotocol.io) server that empowers AI coding assistants (Claude Desktop, Google Antigravity, Cursor, Zed, Hermes) with comprehensive, non-destructive web security auditing, cryptographic analysis, and reconnaissance capabilities.

**SecLens-MCP** یک سرور مستقل پروتکل کانتکست مدل (MCP) به زبان راست است که دستیارهای هوش مصنوعی توسعه‌دهندگان را به یک اسکنر و ممیز امنیتی پرسرعت، هم‌روند و غیرمخرب برای بررسی هدرهای دفاعی، نشت فایل‌های حساس، پیکربندی CORS، توکن‌های JWT، گواهینامه‌های SSL/TLS، بهداشت DNS/ایمیل و سکرت‌های محلی مجهز می‌کند.

---

## 🛠 Features & Tool Suite (10 Security Auditing Tools)

| Tool Name | Scope & Category | Description (EN) | توضیحات فارسی |
| :--- | :--- | :--- | :--- |
| **`generate_security_report`** | Orchestrated Assessment | Master orchestration executing full audit across perimeter, DNS, email, and TLS with OWASP/CWE mappings and executive remediation roadmap. | گزارش ارکستره‌شده و جامع وضعیت امنیتی با امتیاز سراسری، ماتریس ریسک OWASP و نقشه راه پچ. |
| **`check_security_headers`** | Web Perimeter | Evaluates CSP, HSTS, XFO, XCTO, Referrer-Policy, Permissions-Policy, cookie flags, and server disclosures with a 0-100 scoring & grading model. | ممیزی هدرهای دفاعی وب، سیستم امتیازدهی امنیتی (A+ تا F)، تحلیل عمیق CSP و بررسی فلگ‌های کوکی. |
| **`detect_exposed_files`** | Exposure & Leaks | Audits 39 critical sensitive files (`.env`, `.git/HEAD`, SQL dumps, Laravel logs, id_rsa) with intelligent Soft-404 anti-false-positive calibration. | کشف ۳۹ مسیر حساس نشت‌کرده با کالیبراسیون هوشمند Soft-404 جهت مهار خطاهای کاذب در سایت‌های SPA. |
| **`audit_cors_policy`** | Access Control | Probes 3 attack origins (arbitrary external, `null` sandbox, and subdomain prefix bypass) detecting credential leakage and origin reflection. | تست پالیسی‌های اشتراک منابع (CORS) با سه پروب تخصصی و هشدار بحرانی انعکاس مبدا همراه با اعتبارسنجی. |
| **`analyze_jwt_token`** | Cryptography & Tokens | Offline inspection of JWTs: detects `alg: "none"`, cracks weak HS256 signatures via local dictionary attack, validates timestamps (`exp`/`nbf`), and detects leaked secrets. | کالبدشکافی آفلاین JWT: کشف `alg: none`، شکستن امضا با دیکشنری ۵۰ پسورد ضعیف و ارزیابی زمان انقضا. |
| **`inspect_tls_certificate`** | Cryptography & TLS | Connects over TLS, inspects X.509 chains, SANs, CA issuer, expiration lifecycle, public key strength (RSA/ECDSA), and flags deprecated SHA-1/MD5 hashes. | شناسنامه کامل گواهینامه SSL/TLS سرور: استخراج SANها، تاریخ انقضا، طول کلید و کشف الگوریتم‌های منسوخ. |
| **`audit_openapi_spec`** | API Security | Audits OpenAPI 3.x and Swagger 2.0 specs for unauthenticated endpoints, exposed admin/debug routes, and unprotected destructive HTTP methods. | ممیزی اسناد Swagger/OpenAPI: شناسایی اندپوینت‌ها و متدهای حساس فاقد احراز هویت و روت‌های ادمین افشاشده. |
| **`check_email_security`** | Domain Hygiene | Direct DNS queries evaluating SPF mechanism validity, RFC 7208 10-lookup limits, DMARC policy enforcement (`reject`/`quarantine`), and DKIM selectors. | ارزیابی ضداسپم و ضدجعل ایمیل (SPF/DMARC/DKIM) با کوئری مستقیم DNS و محاسبه شاخص مقاومت در برابر فیشینگ. |
| **`check_dns_resilience`** | DNS Infrastructure | Checks CAA certificate issuance scoping, DNSSEC cryptographic signing (DNSKEY/DS), and scans dangling CNAMEs for Subdomain Takeover risks. | ممیزی رکوردهای CAA، تایید امضای دیجیتال DNSSEC و کشف رکوردهای معلق CNAME مستعد آسیب‌پذیری Takeover. |
| **`scan_hardcoded_secrets`** | Local Static SAST | Scans codebase for 15+ API keys (Telegram, OpenAI, Anthropic, Gemini, Groq, Stripe, AWS, DB URIs) and uncatalogued tokens via Shannon Entropy (>4.5). | اسکنر محلی اسرار: کشف ۱۵+ کلید ابری، توکن‌های دیتابیس و رشته‌های تصادفی با محاسبه آنتروپی شانون و ماسک امن. |

---

## ⚡ Installation & Quick Start | نصب و راه‌اندازی

### 🐧 Linux & 🍎 macOS (One-Liner Install)
```bash
curl -fsSL https://raw.githubusercontent.com/thetuxify/seclens-mcp/main/install.sh | bash
```

### 🪟 Windows (PowerShell)
```powershell
iwr -useb https://raw.githubusercontent.com/thetuxify/seclens-mcp/main/install.ps1 | iex
```

### 📦 Build from Source | کامپایل از سورس
```bash
git clone https://github.com/thetuxify/seclens-mcp.git
cd seclens-mcp/src
cargo build --release
# The standalone binary will be available at target/release/seclens-mcp
```

---

## 🔌 Integration Configurations | اتصال به دستیارهای هوش مصنوعی

SecLens communicates over standard JSON-RPC 2.0 on `stdin`/`stdout`. Ready-to-use configuration files are provided in [`integrations/`](./integrations):

### 1. Claude Desktop
Add to your `claude_desktop_config.json`:
* **macOS:** `~/Library/Application Support/Claude/claude_desktop_config.json`
* **Windows:** `%APPDATA%\Claude\claude_desktop_config.json`
* **Linux:** `~/.config/Claude/claude_desktop_config.json`

```json
{
  "mcpServers": {
    "seclens": {
      "command": "seclens-mcp",
      "args": []
    }
  }
}
```

### 2. Cursor IDE
In Cursor **Settings > Features > MCP**, click **Add New MCP Server**:
* **Name:** `seclens`
* **Type:** `stdio`
* **Command:** `seclens-mcp`

### 3. Google Antigravity
Add to your Antigravity MCP settings:
```json
{
  "mcpServers": {
    "seclens": {
      "command": "seclens-mcp",
      "args": []
    }
  }
}
```

### 4. Zed Editor
Add to `~/.config/zed/settings.json`:
```json
{
  "context_servers": {
    "seclens": {
      "command": {
        "path": "seclens-mcp",
        "args": []
      }
    }
  }
}
```

---

## 🛡️ Engineering & Security Principles

1. **Pure Rustls & Zero Native Dependencies:** Built without system OpenSSL dependencies. Completely self-contained and cross-platform across Linux (glibc & static musl), macOS, and Windows.
2. **Zero-Panic Runtime Policy:** Runtime code strictly utilizes `Result<T, E>`. In the event of network timeouts, parse failures, or unreachable hosts, clean errors are reported without crashing the server process.
3. **Strict Channel Isolation:** Standard output (`stdout`) is 100% reserved for JSON-RPC frames. All diagnostic logging uses `tracing` and is routed exclusively to `stderr`.
4. **Passive & Non-Destructive:** Designed for defensive reconnaissance and posture validation. Strictly adheres to rate limits and avoids denial-of-service or aggressive payload testing.

---

## 📜 License

Licensed under the [MIT License](./LICENSE). Created with precision by **Tuxify** (CyberGold Noir Edition).
