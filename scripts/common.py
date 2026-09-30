"""Shared helpers for the lab scripts: rules, fixtures, declared exclusions and the pass/fail judge."""

from __future__ import annotations

import json
from dataclasses import dataclass
from pathlib import Path

import yaml

ROOT = Path(__file__).resolve().parent.parent
PLATFORMS = ("windows", "linux", "azure")
BACKENDS = ("splunk", "lucene", "esql", "kusto")
ENGINES = ("zircolite", "elasticsearch")
TARGETS = BACKENDS + ENGINES
KINDS = ("unsupported", "not-applicable")
POLARITIES = ("positive", "negative")


@dataclass
class Rule:
    slug: str
    platform: str
    path: Path
    docs: list[dict]

    @property
    def primary(self) -> dict:
        """The document that carries the rule's metadata: the correlation document if there is one."""
        return next((d for d in self.docs if "correlation" in d), self.docs[0])

    @property
    def is_correlation(self) -> bool:
        return any("correlation" in d for d in self.docs)


def load_rules(rules_dir: Path) -> list[Rule]:
    rules = []
    for platform in PLATFORMS:
        for path in sorted((rules_dir / platform).glob("*.yml")):
            docs = [d for d in yaml.safe_load_all(path.read_text(encoding="utf-8")) if d is not None]
            rules.append(Rule(path.stem, platform, path, docs))
    return rules


class FixtureError(ValueError):
    pass


@dataclass
class Fixture:
    path: Path
    polarity: str
    events: list[dict]

    @property
    def ids(self) -> set[str]:
        return {e["TestEventId"] for e in self.events}


def read_jsonl(path: Path) -> list[dict]:
    events = []
    for n, line in enumerate(path.read_text(encoding="utf-8").splitlines(), 1):
        if not line.strip():
            continue
        try:
            event = json.loads(line)
        except json.JSONDecodeError as exc:
            raise FixtureError(f"{path}:{n}: invalid JSON ({exc.msg})") from None
        if not isinstance(event, dict):
            raise FixtureError(f"{path}:{n}: event is not a JSON object")
        if not isinstance(event.get("TestEventId"), str) or not event["TestEventId"]:
            raise FixtureError(f"{path}:{n}: missing TestEventId")
        events.append(event)
    if not events:
        raise FixtureError(f"{path}: no events")
    return events


def load_fixtures(events_dir: Path, slug: str) -> list[Fixture]:
    return [
        Fixture(path, polarity, read_jsonl(path))
        for polarity in POLARITIES
        for path in sorted((events_dir / slug / polarity).glob("*.jsonl"))
    ]


@dataclass(frozen=True)
class Exclusion:
    kind: str
    reason: str


def load_support(path: Path) -> dict[tuple[str, str], Exclusion]:
    data = yaml.safe_load(path.read_text(encoding="utf-8")) or {}
    out: dict[tuple[str, str], Exclusion] = {}
    for item in data.get("exclusions") or []:
        kind, reason = item.get("kind"), str(item.get("reason") or "").strip()
        if kind not in KINDS:
            raise ValueError(f"support.yaml: {item.get('rule')}: kind must be one of {KINDS}")
        if not reason:
            raise ValueError(f"support.yaml: {item.get('rule')}: reason is required")
        for target in item.get("targets") or []:
            if target not in TARGETS:
                raise ValueError(f"support.yaml: {item.get('rule')}: unknown target {target!r}")
            out[(item["rule"], target)] = Exclusion(kind, reason)
    return out


def load_targets(path: Path) -> dict:
    return yaml.safe_load(path.read_text(encoding="utf-8"))


def judge(slug: str, fixture: Fixture, matched: set[str], correlation: bool) -> list[str]:
    """Pass/fail for one fixture file. Positives: every event fires (correlation: at least one alert).
    Negatives: nothing fires."""
    name = f"{slug}: {fixture.polarity}/{fixture.path.name}"
    if fixture.polarity == "negative":
        return [f"{name}: fired on {', '.join(sorted(matched))}"] if matched else []
    if correlation:
        return [] if matched else [f"{name}: no correlation alert"]
    missing = fixture.ids - matched
    return [f"{name}: did not match {', '.join(sorted(missing))}"] if missing else []
