---
title: "Detection-as-Code with Sigma"
id: "lab-06-detection-as-code"
category: "Threat Detection & SIEM"
type: "Lab"
status: "completed"
date: "2026-09-30"
time_to_reproduce: "30–60 minutes (fork, enable Actions, apply the ruleset)"
skills: [Sigma, sigma-cli, pySigma, Zircolite, Elasticsearch, Splunk SPL, ES|QL, KQL, Microsoft Sentinel, Sysmon, auditd, GitHub Actions, Python, pytest]
frameworks: [MITRE ATT&CK v19, Sigma specification, NIST CSF 2.0 (DE.CM, DE.AE)]
repo: "https://github.com/santorest/lab-06-detection-as-code"
bundle: "Published on the portfolio site with its SHA-256 checksum"
---

# Detection-as-Code with Sigma

> **TL;DR:** Fifteen ATT&CK-mapped Sigma rules (seven Windows, three Linux auditd, five Azure) live in Git and are
> tested like code. Every pull request lints them, converts them to four SIEM query languages and compares the output
> with committed "golden" files, and **executes** them against positive and negative sample events on two engines
> (Zircolite and Elasticsearch). A branch ruleset blocks the merge unless all ten checks pass.
> **The CI runs are real; the sample events are synthetic**, hand-written from documented log schemas.

| | |
|---|---|
| **Role played** | Detection engineer turning a handful of SIEM searches into a reviewed, tested rule repository |
| **Environment** | Public GitHub repository, GitHub-hosted Ubuntu runners, Elasticsearch 9.5.3 service container |
| **Tools** | Sigma, sigma-cli 3.1.0 / pySigma 1.5.1, Zircolite 4.1.0, Elasticsearch, Python, pytest, gitleaks |
| **Deliverable** | 15 rules, 68 fixture files, golden conversions, 7 CI jobs (10 checks), branch ruleset, 2 demo PRs, results |

---

## 1. Problem

Detections rot quietly. A field renamed in a parser, a typo in a rule, or an edit that makes a rule "catch more"
does not fail anything; the SIEM just stops alerting, or starts alerting on everything. Writing rules once as
vendor-neutral Sigma and treating them like code (reviewed, versioned, tested on every change) turns those silent
failures into red pull requests.

## 2. The rules

| Platform | Rule | ATT&CK |
|---|---|---|
| Windows (Sysmon 1) | PowerShell started with an encoded command | T1059.001 |
| Windows (Sysmon 10) | LSASS process memory opened with read access | T1003.001 |
| Windows (Security 4732) | Member added to the local Administrators group | T1098 |
| Windows (Sysmon 1) | Scheduled task created with schtasks | T1053.005 |
| Windows (Security 1102) | Security event log cleared | T1685.005 |
| Windows (Sysmon 1) | Volume shadow copies deleted | T1490 |
| Windows (System 7045) | Service installed from a user-writable path | T1543.003 |
| Linux (auditd EXECVE) | Reverse shell through /dev/tcp or /dev/udp | T1059.004 |
| Linux (auditd PATH) | SSH authorized_keys file created or modified | T1098.004 |
| Linux (auditd PATH) | Cron persistence file written | T1053.003 |
| Azure Activity | Owner or User Access Administrator role assigned | T1098 |
| Azure Activity | NSG rule allows inbound traffic from the Internet | T1686.001 |
| Entra audit | Conditional Access policy created, changed or deleted | T1556 |
| Azure Activity | Mass resource deletion by one caller (correlation rule) | T1485 |
| Entra sign-in | Successful sign-in from a country outside the allow-list | T1078 |

The five Azure rules re-express the hand-written KQL detections of Lab 05 (Azure landing zone) in Sigma. Every rule
carries a description, references, false-positive notes and a level, and `check_metadata.py` enforces this in CI.
Tags follow ATT&CK v19.

## 3. The pipeline

- **lint**: `sigma check` (validators on, ATT&CK data pinned to v19.2), yamllint, and a metadata/fixture check.
- **convert**: each rule is converted to Splunk SPL, Elastic Lucene, ES|QL and Sentinel KQL, and the output is
  diffed against `tests/expected/`. A change in a rule, a pipeline or a backend version shows up as a reviewable
  diff of the generated query.
- **match-zircolite** and **match-elasticsearch**: every fixture file is run through two engines. Positive files
  must fire on every event (on the correlation rule, at least one alert), negative files are near misses that must
  stay silent. Two engines because a query can be right in one and wrong in another: Elasticsearch keyword fields
  are case-sensitive unless normalised, while Sigma is case-insensitive. The Elasticsearch engine runs a raw-field
  Lucene conversion (not the ECS-mapped golden) on a test index whose strings are lowercase-normalised.
- **coverage** keeps the README ATT&CK table and a Navigator layer in sync with the rule tags; **python** tests the
  scripts; **secrets** runs gitleaks over the full history.

## 4. Declared gaps

Not every rule converts to every target, and the pipeline says so instead of skipping quietly. `support.yaml`
lists each gap with its reason: the correlation rule (no Lucene or kusto support), four Windows rules that the
Sentinel `microsoft_xdr` mapping has no table for, and the auditd rules (no standard Sentinel table). CI re-runs
every "unsupported" conversion and fails once it starts working, so the list cannot go stale.

## 5. Sigma vs the hand-written KQL in Lab 05

| Detection | Lab 05 KQL | Converted from Sigma (`tests/expected/kusto/`) |
|---|---|---|
| Privileged role assignment | Parses the request body and checks `RoleDefinitionId` | `Properties contains "<role GUID>"`: a substring match on the whole properties blob, coarser |
| NSG open to the Internet | Parses the rule JSON and checks direction, access and source prefix | Substring matches on compact JSON: breaks if the body is formatted differently |
| Conditional Access change | Same operations; no filter on the result | Same operations, **plus** `Result =~ "success"`, so failed attempts no longer alert |
| Mass resource deletion | `summarize count() by Caller` over the rule's 15-minute period | **No KQL**: the kusto backend does not support correlation rules (Splunk and ES|QL do) |
| Sign-in outside allowed countries | Allow-list `US`; skips empty `Location` | Allow-list `CO, US`; no empty-`Location` check, so it would fire on sign-ins with no location |

Sigma buys portability and testability. What it costs is the precision of hand-written KQL wherever the data is
nested JSON.

## 6. Results

All numbers below come from GitHub Actions runs on 2026-09-30.

**Baseline run on `main`** ([run 36758372626](https://github.com/santorest/lab-06-detection-as-code/actions/runs/36758372626),
commit `b2357e6`): all 10 checks passed on the first run, in about one minute wall-clock (jobs run in parallel;
the slowest, `match-elasticsearch`, took 56 s including the service start).

| Check | Result |
|---|---|
| `lint` | `sigma check`: 0 errors, 0 issues; metadata OK |
| `convert` (4 jobs) | 0 errors each: 15 Splunk, 14 Lucene, 15 ES\|QL and 7 KQL queries equal their golden files |
| `match-zircolite` | 64 fixture files, 0 failures |
| `match-elasticsearch` | 58 fixture files, 0 failures (the correlation rule's 6 files are a declared skip) |
| `python` | 76 unit tests passed |
| `coverage`, `secrets` | passed |

Both mixed-case positives (`PowerShell.EXE -ENC`, `SCHTASKS /CREATE`) fired on both engines. On the Elasticsearch
side that holds for this repo's test index, where every string is lowercase-normalised. It says nothing about the
committed ECS goldens: they are not executed, and on a standard ECS index their `process.command_line` wildcards
and ES|QL `like` / `==` comparisons are case-sensitive (per Elastic's documentation; not tested here).

**Ruleset** `24264960` on `main`: pull request required, all 10 checks required and up to date, linear history, no
force pushes or deletion.

**Two demo pull requests, both blocked** (closed unmerged). Each one also refreshed the golden files, as a real
author would, so the converters had nothing to object to: every generated query was valid.

| PR | Change | What failed | Merge |
|---|---|---|---|
| [#2](https://github.com/santorest/lab-06-detection-as-code/pull/2) | Over-broad edit: the schtasks rule no longer requires `/create` | `match-zircolite` and `match-elasticsearch`: negatives `neg-query` (`schtasks /query`) and `neg-delete` fired, 2 failures on each engine ([run](https://github.com/santorest/lab-06-detection-as-code/actions/runs/36759000558)) | Blocked |
| [#3](https://github.com/santorest/lab-06-detection-as-code/pull/3) | Field-name typo: `TargetSid` → `TargetUserSid` | Both match jobs: positive `admin-added` no longer matched, 1 failure on each engine ([run](https://github.com/santorest/lab-06-detection-as-code/actions/runs/36758992510)) | Blocked |

The other eight checks passed on both PRs. That is the point: lint and conversion alone would have let both changes
through.

**After the final-review fixes** ([PR #5](https://github.com/santorest/lab-06-detection-as-code/pull/5),
[run 36767918569](https://github.com/santorest/lab-06-detection-as-code/actions/runs/36767918569)): all 10 checks
passed; Zircolite 68 fixture files and Elasticsearch 62, 0 failures on each; 79 unit tests. The four new fixtures
cover the review's findings (section 7).

## 7. Lessons

- **The negative fixtures earned their place first.** The NSG rule as first written matched every source: a bare
  `*` inside a Sigma value is a wildcard, so `"sourceAddressPrefix":"*"` matched `VirtualNetwork` too. The
  near-miss fixture caught it before the rule ever reached `main`; the asterisk is now escaped.
- **Lint against a pinned ATT&CK.** pySigma validates tags against the ATT&CK `master` branch. Mid-build that was
  v19, which split Defense Evasion and renumbered techniques, and `sigma check` began failing on tags that were
  valid the day before. The check now uses a versioned ATT&CK file at a fixed commit.
- **Mappings can silently change a rule.** Sending Security-log rules to Sentinel's `SecurityEvent` table through
  a custom pipeline looked like it worked, but combined with `microsoft_xdr` it dropped the `EventID` condition
  (the 4732 query would also match 4733). Reading the generated query made that visible, and the gap is now declared
  instead.
- **Types matter across backends.** Writing `ResultType` as a number satisfied the Sigma validator but produced
  `ResultType == 0` in KQL, a type error against a string column.
- **Correlation semantics differ by engine.** Splunk and ES|QL conversions count in fixed 15-minute buckets.
  Zircolite uses a sliding window and catches a burst from 13:10 to 13:19 that, reading the queries, the fixed
  buckets would split 5 + 5.
- **Engines have quirks.** Zircolite strips underscores from field names, and a correlation rule only converts
  when it is in the same file as its base rule.
- **A second reader finds the variants you didn't write down.** The final review found three gaps the fixtures did
  not cover: PowerShell accepts every prefix of `-EncodedCommand` (`-Encoded` slipped through), a dumper renamed
  `MsMpEng.exe` outside Defender's folder bypassed the LSASS filter, and `bash -l -c` puts the payload in `a3`.
  Each became a positive fixture that failed first, then passed once the rule was fixed.

## 8. Limits

- The events are synthetic. The tests show each rule matches what it claims and ignores its near misses. They do
  not measure false-positive rates on real telemetry, which needs a baseline in a live environment.
- No Wazuh conversion (out of scope, on the roadmap).
- Elasticsearch is exercised only in CI (Docker service); Zircolite runs locally too.
- What Elasticsearch executes is a raw-field Lucene conversion on a lowercase-normalised test index. The ECS-mapped
  Lucene and ES|QL goldens, Splunk and KQL are generated and diffed, not executed.
- The auditd rules assume decoded records: raw auditd hex-encodes EXECVE arguments that contain spaces, so the
  collector must interpret them first (`ausearch -i`, laurel or auditbeat).

## 9. Reproduce it

1. Fork the repository and enable GitHub Actions.
2. Apply `.github/rulesets/main.json` as a branch ruleset (Settings → Rules → Import).
3. Locally: `python -m venv .venv`, `pip install -r requirements-dev.txt`, then run the commands in the README.
4. Open a pull request that edits a rule and watch the ten checks.

## 10. Mapping

- **MITRE ATT&CK v19:** 14 techniques across 7 tactics (table and Navigator layer in the repository).
- **NIST CSF 2.0:** DE.CM (continuous monitoring) and DE.AE (adverse event analysis): detections as maintained,
  tested assets.
