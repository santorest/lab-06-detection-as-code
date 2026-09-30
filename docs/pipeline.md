# The pipeline

Workflow: [`.github/workflows/ci.yml`](../.github/workflows/ci.yml). Every job runs on `ubuntu-24.04`, with actions
pinned to commit SHAs and `permissions: contents: read`. The ruleset in
[`.github/rulesets/main.json`](../.github/rulesets/main.json) makes all ten checks required on `main`.

## Jobs

- **lint**: `scripts/sigma_check.py --fail-on-issues -c sigma-validation.yml rules/`, `yamllint --strict .` and
  `scripts/check_metadata.py`. `sigma_check.py` is a thin wrapper around `sigma check` that points pySigma's
  ATT&CK data at `enterprise-attack-19.2.json` at a fixed commit of `mitre-attack/attack-stix-data`. Without it,
  pySigma downloads the latest ATT&CK from the `master` branch, so a new ATT&CK release could fail CI overnight.
- **convert** (matrix: splunk, lucene, esql, kusto): `scripts/convert.py --backend <b>` converts each rule with the
  arguments in `targets.yaml` and compares the result with `tests/expected/<b>/<slug>.txt`. It also fails on a
  golden file for an excluded pair, on an orphan golden, and on a stale `unsupported` exclusion (it re-runs the
  conversion and fails if it now succeeds).
- **match-zircolite**: `scripts/get_zircolite.py` downloads the Zircolite 4.1.0 standalone binary and checks its
  SHA-256; `scripts/check_matches.py` runs it once per fixture file and compares the matched `TestEventId`s with
  what the file must (positive) or must not (negative) produce. A non-zero exit, a missing output file or
  unreadable output is a failure, never "no matches".
- **match-elasticsearch**: an `elasticsearch:9.5.3` service container (pinned by digest, security disabled, CI
  only). `scripts/es_matches.py` creates one index per fixture file, where every string is a `keyword` with a
  lowercase normalizer so matching is case-insensitive like Sigma, bulk-loads the events, runs the rule's Lucene
  conversion as a `query_string` query, and applies the same pass/fail judge.
- **coverage**: `scripts/attack_coverage.py --check` regenerates the README table and
  `coverage/attack-navigator.json` from the rule tags and fails if either differs.
- **python**: ruff (lint and format) and pytest for the scripts.
- **secrets**: gitleaks over the full history (official image pinned by digest).

## Field mappings

Golden conversions use realistic mappings: `splunk_windows`; `ecs_windows` for Lucene and ES|QL (ES|QL needs
`--disable-pipeline-check`); `microsoft_xdr` for Windows KQL; for Azure KQL, `azure_monitor` plus
[`pipelines/azure_sentinel.yml`](../pipelines/azure_sentinel.yml), which maps this repo's field names to
`AzureActivity`, `AuditLogs` and `SigninLogs` columns. The match engines use the raw field names of the fixtures
(`sysmon` + `windows-logsources` pipelines for Windows, no mapping elsewhere), so both engines see exactly what the
fixture files contain.

## Findings from building it

These came up while building the lab (2026-09-30, sigma-cli 3.1.0 / pySigma 1.5.1, Zircolite 4.1.0):

- A correlation rule only converts when it is in the same YAML file as its base rule.
- Correlation support: Splunk and ES|QL convert `event_count`; the Lucene and kusto backends refuse it.
- Splunk (`bin _time span=15m`) and ES|QL (`date_trunc(15minutes, ...)`) count in fixed 15-minute buckets.
  Zircolite uses a sliding window: a burst of ten deletes from 13:10 to 13:19 raises an alert in Zircolite (fixture
  `positive/02-across-bucket-boundary.jsonl`), but read as queries, the fixed buckets would split it 5 + 5.
  The Splunk and ES|QL behaviour is read from the generated queries, not executed here.
- Zircolite removes underscores from field names, so fixtures use `TestEventId` and no `Provider_Name`-style fields.
- The kusto `microsoft_xdr` pipeline has no table for Sysmon process access, Security 4732/1102 or System 7045. A
  custom pipeline sending Security-log rules to `SecurityEvent` was tried: combined with `microsoft_xdr`, it silently
  dropped the `EventID` condition (the 4732 query would also match 4733, and the 1102 query came out empty), so it
  was rejected and the gaps are declared instead.
- A numeric `ResultType: 0` renders as `ResultType == 0` in KQL, a type error against the string `SigninLogs`
  column, so rule 15 keeps the string `'0'` (with a per-rule `number_as_string` validator exclusion).
- A bare `*` inside a Sigma value is a wildcard: the NSG rule's `"sourceAddressPrefix":"*"` first matched every
  source. A negative fixture (`VirtualNetwork` source) caught it; the asterisk is now escaped.
- ATT&CK v19 split Defense Evasion into Stealth and Defense Impairment and renumbered techniques (Clear Windows
  Event Logs T1070.001 → T1685.005, Cloud Firewall T1562.007 → T1686.001).

## Pins that are bumped by hand

Dependabot updates `requirements*.txt` and the actions. It does not see:

- the Zircolite version and SHA-256 values in `scripts/get_zircolite.py`
- the Elasticsearch image digest in `ci.yml`
- the gitleaks image digest in `ci.yml`
- the ATT&CK data URL in `scripts/sigma_check.py` (when moving to a new ATT&CK version, re-check every tag)
