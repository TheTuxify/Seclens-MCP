# SKILL: MCP PROTOCOL DESIGN (RUST)
## مهارت پیاده‌سازی پروتکل Model Context Protocol با JSON-RPC 2.0

این مستند ساختار فنی پکت‌های تبادل‌شده بین سرور SecLens و کلاینت هوش مصنوعی را مشخص می‌کند.

---

### ۱. قالب‌بندی فریم‌ها روی Stdio
- ارتباط در لایه Stdio بر پایه خطوط جداشده با `\n` (Newline-delimited JSON) است.
- هر درخواست از کلاینت یک خط JSON کامل است:
```json
{"jsonrpc": "2.0", "id": 1, "method": "initialize", "params": {"protocolVersion": "2024-11-05", "capabilities": {}, "clientInfo": {"name": "claude-code", "version": "1.0"}}}
```
- پاسخ سرور نیز باید دقیقاً در یک خط بازگردانده شود:
```json
{"jsonrpc": "2.0", "id": 1, "result": {"protocolVersion": "2024-11-05", "capabilities": {"tools": {}}, "serverInfo": {"name": "seclens-mcp", "version": "0.1.0"}}}
```

---

### ۲. پاسخ به متد `tools/list`
```json
{
  "jsonrpc": "2.0",
  "id": 2,
  "result": {
    "tools": [
      {
        "name": "check_security_headers",
        "description": "Scans and evaluates HTTP security headers (CSP, HSTS, CORS, X-Frame-Options) for a target URL.",
        "inputSchema": {
          "type": "object",
          "properties": {
            "url": {
              "type": "string",
              "description": "Target website URL (e.g. https://example.com)"
            }
          },
          "required": ["url"]
        }
      }
    ]
  }
}
```

---

### ۳. قالب پاسخ اجرای ابزار `tools/call`
```json
{
  "jsonrpc": "2.0",
  "id": 3,
  "result": {
    "content": [
      {
        "type": "text",
        "text": "## SecLens Security Header Audit Report\nTarget: https://example.com\n..."
      }
    ],
    "isError": false
  }
}
```

---

### ۴. کدهای خطای استاندارد JSON-RPC
- `-32700`: Parse error (JSON نامعتبر)
- `-32600`: Invalid Request (ساختار پکت غلط)
- `-32601`: Method not found (متد ناشناخته)
- `-32602`: Invalid params (پارامترهای اشتباه)
- `-32603`: Internal error (خطای داخلی سرور)
