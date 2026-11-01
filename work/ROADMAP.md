# ROADMAP: SecLens-MCP
## نقشه راه نسخه‌ها و توسعه سوئیت امنیتی

---

### نسخه v0.1.0: هسته اولیه و ماژول وب (Foundation & Web Surface)
- [x] راه‌اندازی شالوده پروژه Cargo و وابستگی‌های Tokio و Serde
- [x] پیاده‌سازی حلقه رویدادهای JSON-RPC 2.0 روی Stdio
- [x] ابزار ۱: `check_security_headers` (ارزیابی کامل CSP, HSTS, X-Frame-Options, X-Content-Type)
- [x] ابزار ۲: `detect_exposed_files` (کشف نشت فایل‌های حساس .git, .env, backups)
- [x] ابزار ۳: `audit_cors_policy` (بررسی رفتارهای پرخطر و آسیب‌پذیری‌های CORS)
- [x] تست دستی با Hermes / Claude Code

### نسخه v0.2.0: هوش رمزنگاری و شناسایی اسناد (Crypto, Tokens & APIs)
- [x] ابزار ۴: `analyze_jwt_token` (دیکود، تست الگوریتم none، پسورد دیکشنری ضعیف و اکسپایر)
- [x] ابزار ۵: `inspect_tls_certificate` (طول کلید، الگوریتم امضا، تاریخ انقضا و زنجیره اعتماد)
- [x] ابزار ۶: `audit_openapi_spec` (پارس و ممیزی امنیتی فایل‌های Swagger/OpenAPI)

### نسخه v0.3.0: زیرساخت و بهداشت دامنه (Infra & Domain Hygiene)
- [x] ابزار ۷: `check_email_security` (استعلام رکوردهای ضداسپم SPF, DKIM, DMARC)
- [x] ابزار ۸: `check_dns_resilience` (بررسی DNSSEC, CAA Records, Subdomain Takeover)
- [x] ابزار ۹: `scan_hardcoded_secrets` (تشخیص پیشرفته با آنتروپی شانون و ۱۵+ امضای ابری، توکن‌ها و دیتابیس)
- [ ] ابزار ۱۰: `audit_dockerfile` (لنتینگ امنیتی فایل‌های داکر و داکر کامپوز)

### نسخه v1.0.0: پکیجینگ و عرضه عمومی (General Availability)
- [x] ابزار ۱۰: `generate_security_report` (ارکستراسیون جامع کل سوئیت ممیزی، ماتریس OWASP/CWE و نقشه راه پچ)
- [x] بهینه‌سازی نهایی کامپایلر Rust (LTO کامل، Codegen Units = 1، Binary Stripping)
- [x] استقلال ۱۰۰٪ از وابستگی‌های نیتیو و سیستم‌عامل با پیاده‌سازی خالص Rustls
- [x] کراس کامپایل خودکار در GitHub Actions برای Linux (x86_64 glibc/musl, aarch64), macOS (Intel, Apple Silicon), Windows (x86_64)
- [x] اسکریپت‌های نصب تک‌دستوری Universal (`install.sh` برای لینوکس/مک و `install.ps1` برای ویندوز)
- [x] فایل‌های کانفیگ آماده برای Antigravity, Claude Desktop, Cursor, Zed و Hermes در `integrations/`
- [x] مستندات دوزبانه جامع در `README.md` با لایسنس MIT آماده انتشار عمومی در **RepoFA**
