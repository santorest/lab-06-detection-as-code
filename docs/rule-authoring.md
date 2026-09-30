# Adding or changing a rule

## 1. The rule file

`rules/<platform>/<slug>.yml`, where `platform` is `windows`, `linux` or `azure` and `slug` is lowercase with
underscores (it names the fixtures and golden files too). `check_metadata.py` requires on the rule (for a
correlation file, on the correlation document):

- `id`: a fresh UUID, unique in the repo (`python -c "import uuid; print(uuid.uuid4())"`)
- `title`, `description`, `author`, `date` (YYYY-MM-DD), `status` (`test`, `stable` or `experimental`), `level`
- `references`: at least one link
- `tags`: at least one technique (`attack.t1059.001`) and one tactic (`attack.execution`), using **ATT&CK v19**
  names; v19 replaced `defense-evasion` with `stealth` and `defense-impairment`
- `falsepositives`: at least one honest note on what else would trigger the rule

Sigma values are case-insensitive, and `*` and `?` are wildcards. To match a literal asterisk, escape it (`\*`) and add
a per-rule `escaped_wildcard` exclusion to `sigma-validation.yml` with a comment saying why.

A correlation rule lives in the **same file** as the base rule it counts (multi-document YAML, `---` between them);
sigma-cli cannot resolve the base rule from another file. The base rule needs a `name`.

## 2. The events

`tests/events/<slug>/positive/*.jsonl` and `negative/*.jsonl`, at least one file each:

- one JSON object per line, flat field names, **no underscores or dots** (Zircolite strips underscores)
- each event has a `TestEventId` unique within the rule
- Windows events carry `Channel` and `EventID`, because the `sysmon` and `windows-logsources` pipelines add
  conditions on them (Sysmon: `Microsoft-Windows-Sysmon/Operational`, EventID 1 process creation, 10 process access)
- negatives should be near misses (same binary, different flag; same operation, failed status), not random noise
- for a correlation rule, each file is one scenario: a positive file must raise an alert, a negative file must not

Everything is synthetic: use `corp.example` accounts and documentation IP ranges (`203.0.113.0/24`,
`198.51.100.0/24`), never real names or captured data.

## 3. Check it

```bash
python scripts/sigma_check.py --fail-on-issues -c sigma-validation.yml rules/
python scripts/check_metadata.py
python scripts/check_matches.py <slug>
python scripts/convert.py --update     # then review the diff of tests/expected/ like code
python scripts/attack_coverage.py      # refreshes the README table and the Navigator layer
```

If a backend cannot convert the rule, the conversion error says why. Declare it in `support.yaml` (`kind:
unsupported` when a tool rejects the rule, `not-applicable` when no meaningful target exists) with the reason. CI
fails on an undeclared conversion failure and on an `unsupported` entry that has started to work.

## Telemetry the rules assume

- **Windows:** Sysmon with process creation (1) and process access (10) logging; Security auditing for security
  group management (4732) and the audit-log-cleared event (1102); the System log (7045).
- **Linux auditd:** `-a always,exit -F arch=b64 -S execve -k exec`, `-w /root/.ssh -p wa -k ssh_keys`,
  `-w /home -p wa -k home_writes`, `-w /etc/cron.d -p wa -k cron`, `-w /etc/crontab -p wa -k cron`,
  `-w /var/spool/cron -p wa -k cron`. The collector must decode the records (`ausearch -i`, laurel or auditbeat):
  raw auditd hex-encodes any EXECVE argument that contains a space, and the rules match decoded text.
- **Azure:** Activity log, Entra audit logs and sign-in logs exported to the SIEM (see Lab 05's landing zone).
