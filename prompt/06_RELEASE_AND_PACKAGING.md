# PROMPT 06: RELEASE, LTO & AUR PACKAGING
## گام ۶: بهینه‌سازی کامپایلر، پکیجینگ تک‌باینری و عرضه در Arch Linux (v1.0.0)

---

```text
/skill :
RUST_ASYNC_ENGINEERING, MCP_PROTOCOL_DESIGN

/rules :
AGENT_RULES, STYLE_GUIDE

/work :
ورژن: v1.0.0 (General Availability)
هدف: بهینه‌سازی نهایی باینری با LTO، نگارش مستندات README دو زبانه و پکیجینگ AUR برای آرچ لینوکس

/prompt :
سلام دارلین، پروژه SecLens-MCP را برای عرضه عمومی و پکیجینگ آماده کن:

۱. بهینه‌سازی `[profile.release]` در `Cargo.toml`:
   - `opt-level = 3`
   - `lto = true`
   - `codegen-units = 1`
   - `panic = "abort"`
   - `strip = true` (کاهش حجم باینری به زیر ۱۰ مگابایت بدون افت کارایی)
۲. فایل `README.md` دو زبانه (انگلیسی و فارسی):
   - معرفی پروژه و معماری سرور
   - راهنمای اضافه کردن به Claude Code, Cursor, Zed, Hermes
   - جدول ابزارها و مثال‌های فراخوانی
   - بج‌های لایسنس MIT، نسخه و لوگوی پروژه
۳. فایل پکیجینگ برای Arch Linux (`PKGBUILD`):
   - جهت نصب ساده در آرچ لینوکس از طریق `makepkg` یا انتشار در مخزن کاربران آرچ (`AUR`).
۴. ساخت ورک‌فلو گیت‌هاب اکشنز (`.github/workflows/release.yml`) برای بیلد خودکار باینری‌های لینوکس و مک.
```
