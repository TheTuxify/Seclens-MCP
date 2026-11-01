# PROMPT 01: INIT FOUNDATION & STDIO MCP LOOP
## گام ۱: راه‌اندازی پروژه Cargo و حلقه پیام‌های MCP Stdio (v0.1.0)

---

```text
/skill :
MCP_PROTOCOL_DESIGN, RUST_ASYNC_ENGINEERING

/rules :
AGENT_RULES, STYLE_GUIDE

/work :
ورژن: v0.1.0 (Foundation)
هدف: پیاده‌سازی حلقه پیام‌های JSON-RPC 2.0 روی Stdio و متدهای initialize و tools/list در Rust

/prompt :
سلام دارلین، پروژه SecLens-MCP را در زبان Rust پیاده‌سازی کن:
۱. در `Cargo.toml` کریت‌های ضروری را تعریف کن:
   - `tokio = { version = "1.40", features = ["full"] }`
   - `serde = { version = "1.0", features = ["derive"] }`
   - `serde_json = "1.0"`
   - `reqwest = { version = "0.12", default-features = false, features = ["rustls-tls", "json", "http2"] }`
   - `thiserror = "1.0"`
   - `tracing` و `tracing-subscriber` (برای ارسال تمام لاگ‌ها فقط به stderr)
۲. ماژول `src/protocol/types.rs`:
   - ساختارهای `JsonRpcRequest`, `JsonRpcResponse`, `ToolDefinition`, `ToolCallRequest`
۳. فایل `src/main.rs`:
   - حلقه رویدادهای `tokio::io::stdin().lines()` برای خواندن پیام‌های کلاینت خط‌به‌خط.
   - هندل کردن درخواست `initialize`: بازگرداندن اطلاعات سرور (نام: `seclens-mcp`, ورژن: `0.1.0`, قابلیت‌ها: `tools`).
   - هندل کردن اعلان `notifications/initialized`: پذیرش بی‌صدا.
   - هندل کردن `tools/list`: بازگرداندن اسکیماهای اولیه ابزارهای امنیتی.
   - هندل کردن `ping`: پاسخ خالی `{}`.
۴. اطمینان حاصل کن هیچ دستور پرینتی به stdout نمی‌رود مگر پکت‌های تمیز JSON-RPC.
```
