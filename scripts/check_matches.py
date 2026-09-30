"""Match engine 1: run the pinned Zircolite binary on every fixture file and judge the result."""

from __future__ import annotations

import json
import subprocess
import sys
import tempfile
from pathlib import Path

from common import ROOT, Fixture, Rule, judge, load_fixtures, load_rules, load_support, load_targets
from get_zircolite import ensure


class ZircoliteError(RuntimeError):
    pass


def matched_ids(results: list[dict]) -> set[str]:
    ids: set[str] = set()
    for rule in results:
        for match in rule.get("matches") or []:
            if match.get("result_type") == "correlation":
                ids.update(
                    e["event"]["TestEventId"]
                    for e in match.get("evidence") or []
                    if "TestEventId" in (e.get("event") or {})
                )
            elif "TestEventId" in match:
                ids.add(match["TestEventId"])
    return ids


def run_zircolite(exe: Path, rule: Path, events: Path, extra: list[str], workdir: Path) -> list[dict]:
    out = workdir / "detected.json"
    out.unlink(missing_ok=True)
    cmd = [str(exe), "--events", str(events), "--ruleset", str(rule), "--jsononly", "-o", str(out), "-q", *extra]
    proc = subprocess.run(cmd, capture_output=True, text=True, cwd=workdir, check=False)
    if proc.returncode != 0:
        raise ZircoliteError(f"exit {proc.returncode}: {(proc.stderr or proc.stdout)[-2000:]}")
    if not out.exists():
        raise ZircoliteError("no output file written")
    try:
        return json.loads(out.read_text(encoding="utf-8"))
    except json.JSONDecodeError as exc:
        raise ZircoliteError(f"unreadable output: {exc}") from None


def check_rule(rule: Rule, fixtures: list[Fixture], extra: list[str], exe: Path, workdir: Path) -> list[str]:
    errors = []
    for fx in fixtures:
        try:
            results = run_zircolite(exe, rule.path, fx.path, extra, workdir)
        except ZircoliteError as exc:
            errors.append(f"{rule.slug}: {fx.polarity}/{fx.path.name}: zircolite failed: {exc}")
            continue
        errors += judge(rule.slug, fx, matched_ids(results), rule.is_correlation)
    return errors


def main(argv: list[str]) -> int:
    exe = ensure(ROOT / ".tools")
    targets = load_targets(ROOT / "targets.yaml")
    support = load_support(ROOT / "support.yaml")
    rules = [r for r in load_rules(ROOT / "rules") if not argv or r.slug in argv]
    errors, checked = [], 0
    with tempfile.TemporaryDirectory() as tmp:
        for rule in rules:
            if (rule.slug, "zircolite") in support:
                print(f"SKIP {rule.slug}: {support[(rule.slug, 'zircolite')].reason}")
                continue
            fixtures = load_fixtures(ROOT / "tests" / "events", rule.slug)
            rule_errors = check_rule(rule, fixtures, targets[rule.platform]["zircolite"], exe, Path(tmp))
            checked += len(fixtures)
            print(f"{'FAIL' if rule_errors else 'ok  '} {rule.slug} ({len(fixtures)} fixture files)")
            errors += rule_errors
    for e in errors:
        print(e)
    print(f"zircolite: {checked} fixture files, {len(errors)} failure(s)")
    return 1 if errors else 0


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
