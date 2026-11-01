# STYLE GUIDE: SecLens-MCP
## راهنمای استایل کدنویسی و معماری در زبان Rust

---

### ۱. معماری لایه‌ای پروژه (`src/`)

```text
src/
├── main.rs            # ورود به برنامه، پردازش خط فرمان و رویدادهای Stdio
├── protocol/          # پروتکل MCP و مدل‌های JSON-RPC 2.0
│   ├── mod.rs
│   ├── types.rs       # ساختارهای Request, Response, Tool, Call
│   └── error.rs       # خطاهای استاندارد JSON-RPC (Code, Message, Data)
├── engine/            # هسته اشتراکی شبکه و منابع سیستم
│   ├── mod.rs
│   └── http.rs        # کلاینت بهینه‌شده Reqwest با Rustls و کانفیگ پولینگ
└── tools/             # ماژول‌های ابزارهای امنیتی
    ├── mod.rs         # ریجستری متمرکز و دیسپچر فرامین
    ├── headers.rs     # اسکن هدرهای امنیتی وب (CSP, HSTS, CORS)
    ├── files.rs       # جستجوی فایل‌های حساس نشت‌کرده (.git, .env)
    ├── jwt.rs         # تحلیل ساختاری و امنیت توکن‌های JWT
    ├── dns.rs         # ارزیابی بهداشت DNS و ایمیل (SPF/DMARC)
    └── secrets.rs     # اسکن محلی سورس‌کد برای کشف پسوردهای هاردکدشده
```

### ۲. استانداردهای زبان Rust
- کد باید فرمت استاندارد `cargo fmt` را رعایت کند.
- خطاهای هشداردهنده `cargo clippy --all-targets` باید صفر باشند.
- برای ماژول‌های پابلیک حتماً از کامنت‌های مستندسازی (`///`) استفاده شود.
- سریالایز کردن فیلدهای غایب در JSON با `#[serde(skip_serializing_if = "Option::is_none")]` انجام شود تا حجم پکت‌های شبکه و ورودی هوش مصنوعی به حداقل برسد.

### ۳. الگوی پیاده‌سازی هر ابزار (Tool Pattern)
هر ابزار در پوشه `src/tools/` باید یک متد مستقل با امضای مشخص داشته باشد:
```rust
pub async fn execute(args: Value, engine: &Engine) -> Result<String, ToolError> {
    // 1. Parse and validate arguments from serde_json::Value
    // 2. Perform concurrent, non-destructive audit
    // 3. Return clean, formatted markdown with actionable findings
}
```
