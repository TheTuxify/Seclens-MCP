# VERSIONING & RELEASE STRATEGY: SecLens-MCP
## استراتژی نسخه‌گذاری، شاخه‌های گیت و انتشار

پروژه از سیستم استاندارد نگارش معنایی (Semantic Versioning - SemVer) پیروی می‌کند:

---

### ۱. جدول شاخه‌های گیت

| شاخه | نقش | وضعیت پایداری |
| :--- | :--- | :--- |
| **`main`** | کد آماده انتشار عمومی (Production-Ready) | پایدار ۱۰۰٪ |
| **`dev`** | شاخه ادغام تغییرات روزانه و اسپرینت‌ها | در حال توسعه |
| **`feat/*`** | شاخه‌های مجزا برای توسعه ابزارها یا قابلیت‌های جدید | آزمایشی |
| **`release/*`**| آماده‌سازی مستندات، افزایش تگ نسخه و تست‌های نهایی | تثبیت نسخه |

---

### ۲. استانداردهای پیام کامیت (Conventional Commits)
- `feat(tools): add check_security_headers tool`
- `fix(protocol): handle malformed jsonrpc requests gracefully`
- `perf(engine): optimize http connection pool and timeout`
- `docs(readme): add mcp configuration guide for cursor and claude`
- `test(headers): add mock tests for hsts and csp rules`
