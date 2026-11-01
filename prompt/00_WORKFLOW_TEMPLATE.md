# PROMPT WORKFLOW TEMPLATE: SecLens-MCP
## قالب استاندارد پرامپت‌نویسی برای هدایت ایجنت

هر زمان در طول توسعه پروژه با ایجنت کدنویسی (مانند Claude Code, Hermes, Cursor) کار می‌کنید، از این ساختار ۴ بخشی استاندارد استفاده کنید:

```text
/skill :
[اسامی اسکیل‌های مرتبط از پوشه skills/ مانند: RUST_ASYNC_ENGINEERING, SECURITY_AUDITING_LOGIC]

/rules :
[قوانین الزامی از پوشه rules/ مانند: AGENT_RULES, STYLE_GUIDE]

/work :
ورژن: [مثلاً v0.1.0]
هدف: [توضیح هدف فنی این اسپرینت]
تسک‌های مورد نظر:
۱. ...
۲. ...

/prompt :
[دستورات و نیازمندی‌های دقیق مرحله به زبان فنی...]
```
