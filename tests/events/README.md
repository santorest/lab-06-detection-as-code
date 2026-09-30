# Test events

Every file here is **synthetic**: hand-written from the published schemas of Sysmon, the Windows Security and System
logs, Linux auditd, and the Azure AzureActivity / AuditLogs / SigninLogs tables. None of it was captured from a real
environment, and no real person or organisation appears in it (`corp.example`, documentation IP ranges).

- One JSON object per line (JSONL), flat field names without dots or underscores (Zircolite strips underscores).
- `TestEventId` identifies the event in engine output; it is unique per rule.
- `positive/` files must fire (every event; for the correlation rule, at least one alert per file).
- `negative/` files are near-misses that must not fire.
