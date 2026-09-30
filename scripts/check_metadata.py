"""Repository lint beyond `sigma check`: rule metadata, fixtures and declared exclusions."""

from __future__ import annotations

import datetime as dt
import re
import sys
import uuid
from pathlib import Path

from common import PLATFORMS, POLARITIES, ROOT, FixtureError, Rule, load_fixtures, load_rules, load_support

TACTICS = frozenset(
    {
        "reconnaissance",
        "resource-development",
        "initial-access",
        "execution",
        "persistence",
        "privilege-escalation",
        "defense-evasion",
        "credential-access",
        "discovery",
        "lateral-movement",
        "collection",
        "command-and-control",
        "exfiltration",
        "impact",
    }
)
TECHNIQUE = re.compile(r"^attack\.t\d{4}(\.\d{3})?$")
STATUSES = {"test", "stable", "experimental"}
LEVELS = {"informational", "low", "medium", "high", "critical"}


def _is_uuid(value: object) -> bool:
    try:
        return isinstance(value, str) and str(uuid.UUID(value)) == value.lower()
    except ValueError:
        return False


def _is_date(value: object) -> bool:
    if isinstance(value, dt.date):
        return True
    try:
        dt.date.fromisoformat(str(value))
        return True
    except ValueError:
        return False


def _non_empty_str_list(value: object) -> bool:
    return isinstance(value, list) and bool(value) and all(isinstance(v, str) and v.strip() for v in value)


def _check_rule(rule: Rule, seen_ids: dict[str, str]) -> list[str]:
    errors = []
    for doc in rule.docs:
        rid = doc.get("id")
        if not _is_uuid(rid):
            errors.append(f"{rule.slug}: id is not a UUID: {rid!r}")
        elif rid in seen_ids:
            errors.append(f"{rule.slug}: duplicate id {rid} (also in {seen_ids[rid]})")
        else:
            seen_ids[rid] = rule.slug
        if not str(doc.get("title") or "").strip():
            errors.append(f"{rule.slug}: title is required")
        if doc.get("status") not in STATUSES:
            errors.append(f"{rule.slug}: status must be one of {sorted(STATUSES)}")
    p = rule.primary
    for key in ("description", "author"):
        if not str(p.get(key) or "").strip():
            errors.append(f"{rule.slug}: {key} is required")
    if not _is_date(p.get("date")):
        errors.append(f"{rule.slug}: date must be YYYY-MM-DD")
    if not _non_empty_str_list(p.get("references")):
        errors.append(f"{rule.slug}: references must be a non-empty list")
    if p.get("level") not in LEVELS:
        errors.append(f"{rule.slug}: level must be one of {sorted(LEVELS)}")
    if not _non_empty_str_list(p.get("falsepositives")):
        errors.append(f"{rule.slug}: falsepositives must be a non-empty list of notes")
    tags = p.get("tags") or []
    if not any(TECHNIQUE.match(str(t)) for t in tags):
        errors.append(f"{rule.slug}: needs an ATT&CK technique tag (attack.tNNNN)")
    if not any(str(t).removeprefix("attack.") in TACTICS for t in tags):
        errors.append(f"{rule.slug}: needs an ATT&CK tactic tag (e.g. attack.execution)")
    if rule.is_correlation:
        names = {d.get("name") for d in rule.docs if "correlation" not in d}
        if None in names:
            errors.append(f"{rule.slug}: every base rule in a correlation file needs a name")
        for ref in (p.get("correlation") or {}).get("rules") or []:
            if ref not in names:
                errors.append(f"{rule.slug}: correlation references unknown rule name {ref}")
    return errors


def _check_fixtures(root: Path, slug: str) -> list[str]:
    errors = []
    events_dir = root / "tests" / "events"
    for polarity in POLARITIES:
        if not list((events_dir / slug / polarity).glob("*.jsonl")):
            errors.append(f"{slug}: no {polarity} fixtures in tests/events/{slug}/{polarity}/")
    try:
        fixtures = load_fixtures(events_dir, slug)
    except FixtureError as exc:
        return [*errors, f"{slug}: {exc}"]
    seen: set[str] = set()
    for fx in fixtures:
        for event in fx.events:
            tid = event["TestEventId"]
            if tid in seen:
                errors.append(f"{slug}: duplicate TestEventId {tid} ({fx.path.name})")
            seen.add(tid)
    return errors


def check_repo(root: Path) -> list[str]:
    errors = []
    rules_dir = root / "rules"
    for path in sorted(p for p in rules_dir.rglob("*") if p.is_file()):
        rel = path.relative_to(rules_dir)
        if len(rel.parts) != 2 or rel.parts[0] not in PLATFORMS or path.suffix != ".yml":
            errors.append(f"rules/{rel.as_posix()}: unexpected file (use rules/<platform>/<slug>.yml)")
    rules = load_rules(rules_dir)
    seen_ids: dict[str, str] = {}
    for rule in rules:
        errors += _check_rule(rule, seen_ids)
        errors += _check_fixtures(root, rule.slug)
    slugs = {r.slug for r in rules}
    events_dir = root / "tests" / "events"
    if events_dir.is_dir():
        for d in sorted(p for p in events_dir.iterdir() if p.is_dir()):
            if d.name not in slugs:
                errors.append(f"tests/events/{d.name}: orphan fixtures (no rule with this slug)")
    try:
        support = load_support(root / "support.yaml")
    except (ValueError, KeyError) as exc:
        return [*errors, f"support.yaml: {exc}"]
    for slug, target in sorted(support):
        if slug not in slugs:
            errors.append(f"support.yaml: excludes unknown rule {slug} ({target})")
    return errors


def main() -> int:
    errors = check_repo(ROOT)
    for e in errors:
        print(e)
    print(f"{len(errors)} error(s)" if errors else "metadata OK")
    return 1 if errors else 0


if __name__ == "__main__":
    sys.exit(main())
