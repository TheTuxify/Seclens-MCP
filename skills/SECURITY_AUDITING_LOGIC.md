# SKILL: SECURITY AUDITING LOGIC
## مهارت منطق تحلیل و ارزیابی آسیب‌پذیری‌ها

این مستند معیارهای دقیق و الگوریتم‌های ممیزی امنیتی ماژول‌های SecLens را تعیین می‌کند.

---

### ۱. تحلیل هدرهای امنیتی (Security Headers Heuristics)

| هدر امنیتی | وضعیت امن (Secure) | شرایط اخطار / بحرانی (Warning/Critical) |
| :--- | :--- | :--- |
| **Strict-Transport-Security (HSTS)** | وجود دارد؛ `max-age` حداقل ۳۱۵۳۶۰۰۰ (۱ سال) همراه با `includeSubDomains`. | غایب است یا مقدار `max-age` کمتر از ۶ ماه است. |
| **Content-Security-Policy (CSP)** | تعریف دقیق `default-src`، مسدود بودن `unsafe-inline` و `unsafe-eval`. | غایب است یا حاوی کلمات `unsafe-inline` و وایلدکارت `*` است. |
| **X-Frame-Options** | `DENY` یا `SAMEORIGIN`. | غایب است (ریسک Clickjacking). |
| **X-Content-Type-Options** | مقدار دقیق `nosniff`. | غایب است (ریسک MIME-confusion). |
| **Referrer-Policy** | `strict-origin-when-cross-origin` یا `no-referrer`. | غایب است یا `unsafe-url`. |
| **Permissions-Policy** | محدودسازی دسترسی سنسورها، دوربین و میکروفون. | غایب است. |
| **Server / X-Powered-By** | حذف‌شده یا مقدار مبهم دارد. | افشای نسخه دقیق وب‌سرور و فریم‌ورک (مانند `nginx/1.18.0` یا `PHP/8.1`). |

---

### ۲. اعتبارسنجی پالیسی‌های CORS (CORS Audit)
- ارسال ریکوئست با هدرهای شبیه‌سازی مهاجم:
  - `Origin: https://evil-attacker.com`
  - `Origin: null`
- **آسیب‌پذیری بحرانی (Critical):**  
  اگر پاسخ سرور شامل موارد زیر باشد:
  `Access-Control-Allow-Origin: https://evil-attacker.com`  
  `Access-Control-Allow-Credentials: true`  
  این نشان‌دهنده اعتماد کورکورانه و امکان سرقت کوکی‌های کاربر توسط وب‌سایت مهاجم است.

---

### ۳. کالبدشکافی توکن JWT (JWT Inspection)
- دیکود بخش Header و Payload بدون نیاز به کلید.
- **بررسی الگوریتم:** هشدار اگر `alg` برابر `none`، `None` یا `NONE` باشد (امکان دور زدن کامل امضا).
- **بررسی کلیدهای ضعیف:** چک کردن امضا با لیست پسوردهای عمومی (`secret`, `password`, `123456`, `jwt_secret`, `admin`).
- **بررسی فیلدهای حساس:** اسکن پیلود برای کشف فیلدهای مشکوک مانند `password`, `hash`, `token`, `private_key`.
- **بررسی انقضا:** بررسی مقدار فیلد `exp` و مقایسه با زمان فعلی UTC.

---

### ۴. کشف فایل‌های حساس (Sensitive File Exposure)
بررسی لیست مشخصی از مسیرهای پرتکرار با متد `HEAD` یا `GET`:
- `.env`, `.env.local`, `.env.production`
- `.git/HEAD`, `.git/config`
- `docker-compose.yml`, `Dockerfile`
- `backup.sql`, `dump.sql`, `db.sqlite3`
- `composer.json`, `package.json`, `requirements.txt`
- `phpinfo.php`, `server-status`
*شرط تأیید:* استاتوس کد ۲۰۰ به همراه بررسی نوع محتوا (بررسی اینکه صفحه ۴۰۴ سفارشی با استاتوس ۲۰۰ فیک نباشد).

---

### ۵. اسکن اسرار و کلیدهای هاردکدشده (Static Secret Scanning)
الگوهای رجکس کامپایل‌شده برای کشف کلیدهای خصوصی در سورس‌کد:
- **Telegram Bot Token:** `[0-9]{8,10}:[a-zA-Z0-9_-]{35}`
- **OpenAI API Key:** `sk-[a-zA-Z0-9T3BlbkFJ]{20,}` یا `sk-proj-[a-zA-Z0-9_-]{40,}`
- **Generic Private Key:** `-----BEGIN (RSA|EC|OPENSSH|PRIVATE) KEY-----`
- **AWS Access Key ID:** `(A3T[A-Z0-9]|AKIA|AGPA|AIDA|AROA|AIPA|ANPA|ANVA|ASIA)[A-Z0-9]{16}`
- **GitHub Personal Token:** `gh[pousr]_[A-Za-z0-9_]{36,255}`
