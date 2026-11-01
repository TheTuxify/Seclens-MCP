# PROMPT 05: HARDCODED SECRETS & SAST SCANNER
## گام ۵: پیاده‌سازی ابزار اسکن محلی سورس‌کد و کشف کلیدهای خصوصی (v0.4.0)

---

```text
/skill :
SECURITY_AUDITING_LOGIC, RUST_ASYNC_ENGINEERING

/rules :
AGENT_RULES, STYLE_GUIDE

/work :
ورژن: v0.4.0
هدف: پیاده‌سازی ابزار scan_hardcoded_secrets برای ممیزی سورس‌کد محلی قبل از کامیت

/prompt :
سلام دارلین، ابزار اسکن اسرار محلی را پیاده‌سازی کن:

۱. ابزار `scan_hardcoded_secrets`:
   - ورودی: `directory_path: String`, `max_files: Optional<usize>`
   - پیمایش بهینه فایل‌سیستم و فیلتر کردن پوشه‌های خروجی بیلد و گیت (`target`, `node_modules`, `.git`, `.venv`).
   - اسکن محتوای فایل‌های متنی با رجکس‌های کامپایل‌شده سریع برای شناسایی:
     * تلگرام بات توکن (`Telegram Bot Token`)
     * کلیدهای دسترسی OpenAI و Claude (`OpenAI / Anthropic Keys`)
     * کلیدهای خصوصی RSA / EC (`-----BEGIN PRIVATE KEY-----`)
     * کلیدهای دسترسی AWS و GitHub PAT
     * الگوهای پسورد هاردکدشده در فیلدهای `password = "..."`
   - خروجی: گزارش امنیتی حاوی مسیر فایل، شماره خط، نوع کلید کشف‌شده و نمایش کلید به صورت ماسک‌شده (فقط ۴ کاراکتر اول و آخر برای حفظ امنیت).
```
