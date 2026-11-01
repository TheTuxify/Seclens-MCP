# PROMPT 04: DNS & EMAIL SPOOFING DEFENSE
## گام ۴: پیاده‌سازی ابزارهای بهداشت دامنه و دفاع در برابر جعل ایمیل (v0.3.0)

---

```text
/skill :
SECURITY_AUDITING_LOGIC, RUST_ASYNC_ENGINEERING

/rules :
AGENT_RULES, STYLE_GUIDE

/work :
ورژن: v0.3.0
هدف: پیاده‌سازی ابزارهای check_email_security و check_dns_resilience با کتابخانه hickory-resolver

/prompt :
سلام دارلین، ابزارهای بهداشت دامنه و ایمیل را پیاده‌سازی کن:

۱. ابزار `check_email_security`:
   - ورودی: `domain: String`
   - استعلام ناهمگام رکوردهای TXT دامنه برای بررسی:
     * رکورد **SPF**: بررسی وجود مکانیزم‌های سخت‌گیرانه (`-all` در برابر `~all` یا `?all`)
     * رکورد **DMARC** در آدرس `_dmarc.<domain>`: بررسی پالیسی (`p=reject`, `p=quarantine`, `p=none`) و آدرس‌های گزارش‌گیری (`rua`, `ruf`)
   - خروجی: وضعیت مقاومت دامنه در برابر حملات فیشینگ و جعل هویت (Spoofing).

۲. ابزار `check_dns_resilience`:
   - ورودی: `domain: String`
   - بررسی حضور رکورد **CAA**: تعیین مراجع مجاز صدور گواهینامه SSL برای جلوگیری از تقلب در صدور سرتیفیکیت.
   - بررسی امضای **DNSSEC**: اطمینان از محافظت دی‌ان‌اس در برابر مسموم‌سازی کش (Cache Poisoning).
```
