# PROMPT 02: WEB SURFACE SECURITY SCANNER
## گام ۲: پیاده‌سازی ابزارهای هدرهای امنیتی، نشت فایل‌ها و CORS (v0.1.0)

---

```text
/skill :
SECURITY_AUDITING_LOGIC, RUST_ASYNC_ENGINEERING

/rules :
AGENT_RULES, STYLE_GUIDE

/work :
ورژن: v0.1.0
هدف: پیاده‌سازی ابزارهای check_security_headers, detect_exposed_files, audit_cors_policy

/prompt :
سلام دارلین، ابزارهای بررسی سطح حمله وب را در پوشه `src/tools/` پیاده‌سازی کن:

۱. ابزار `check_security_headers`:
   - ورودی: `url: String`
   - تحلیل هدرهای بازگشتی: HSTS, CSP, X-Frame-Options, X-Content-Type-Options, Referrer-Policy, Permissions-Policy, Server.
   - خروجی: جدول مارک‌داون تمیز شامل نام هدر، استاتوس (Pass / Warn / Fail) و توضیحات ریسک بر اساس استانداردهای OWASP.

۲. ابزار `detect_exposed_files`:
   - ورودی: `url: String`
   - ارسال ریکوئست‌های ناهمگام با سقف هم‌روندی (Semaphore) برای کشف ۲۰ مسیر حساس:
     `.env`, `.git/HEAD`, `backup.sql`, `docker-compose.yml`, `config.json` و...
   - فیلتر هوشمند: بررسی هدر `Content-Type` و طول بادی برای جلوگیری از تشخیص اشتباه صفحات ۴۰۴ سفارشی.

۳. ابزار `audit_cors_policy`:
   - ورودی: `url: String`
   - ارسال دو پروب با هدرهای `Origin: https://attacker.com` و `Origin: null`.
   - تشخیص و اخطار در صورت انعکاس داینامیک Origin به همراه فلگ `credentials: true`.
```
