from pathlib import Path

import pytest
from common import (
    Exclusion,
    Fixture,
    FixtureError,
    judge,
    load_fixtures,
    load_rules,
    load_support,
    read_jsonl,
)
from conftest import CORRELATION_RULE, write_events


def test_load_rules_reads_platform_and_slug(repo: Path):
    [rule] = load_rules(repo / "rules")
    assert (rule.slug, rule.platform) == ("proc_creation_test_enc", "windows")
    assert rule.primary["title"] == "Test encoded command"
    assert not rule.is_correlation


def test_correlation_rule_primary_is_correlation_doc(repo: Path):
    (repo / "rules" / "azure").mkdir()
    (repo / "rules" / "azure" / "activity_mass_test.yml").write_text(CORRELATION_RULE, encoding="utf-8")
    rule = next(r for r in load_rules(repo / "rules") if r.platform == "azure")
    assert rule.is_correlation
    assert rule.primary["title"] == "Mass delete"
    assert len(rule.docs) == 2


def test_load_fixtures_by_polarity(repo: Path):
    fixtures = load_fixtures(repo / "tests" / "events", "proc_creation_test_enc")
    assert [(f.polarity, f.ids) for f in fixtures] == [("positive", {"p1"}), ("negative", {"n1"})]


@pytest.mark.parametrize(
    ("content", "message"),
    [
        ("", "no events"),
        ("\n\n", "no events"),
        ("{not json}\n", ":1: invalid JSON"),
        ('﻿{"TestEventId": "a"}\n', ":1: invalid JSON"),
        ("[1, 2]\n", ":1: event is not a JSON object"),
        ('{"a": 1}\n', ":1: missing TestEventId"),
        ('{"TestEventId": ""}\n', ":1: missing TestEventId"),
    ],
)
def test_read_jsonl_rejects_malformed(tmp_path: Path, content: str, message: str):
    p = tmp_path / "bad.jsonl"
    p.write_text(content, encoding="utf-8")
    with pytest.raises(FixtureError, match=message):
        read_jsonl(p)


def test_load_support(tmp_path: Path):
    p = tmp_path / "support.yaml"
    p.write_text(
        "exclusions:\n  - rule: r1\n    targets: [lucene, kusto]\n    kind: unsupported\n    reason: No correlation.\n",
        encoding="utf-8",
    )
    assert load_support(p) == {
        ("r1", "lucene"): Exclusion("unsupported", "No correlation."),
        ("r1", "kusto"): Exclusion("unsupported", "No correlation."),
    }


@pytest.mark.parametrize(
    "entry",
    [
        "  - rule: r1\n    targets: [wazuh]\n    kind: unsupported\n    reason: x\n",
        "  - rule: r1\n    targets: [lucene]\n    kind: maybe\n    reason: x\n",
        "  - rule: r1\n    targets: [lucene]\n    kind: unsupported\n    reason: ''\n",
    ],
)
def test_load_support_rejects_bad_entries(tmp_path: Path, entry: str):
    p = tmp_path / "support.yaml"
    p.write_text("exclusions:\n" + entry, encoding="utf-8")
    with pytest.raises(ValueError):
        load_support(p)


def _fx(tmp_path: Path, polarity: str, ids: list[str]) -> Fixture:
    p = tmp_path / f"{polarity}.jsonl"
    write_events(p, [{"TestEventId": i} for i in ids])
    return Fixture(p, polarity, read_jsonl(p))


def test_judge_positive_requires_every_event(tmp_path: Path):
    fx = _fx(tmp_path, "positive", ["a", "b"])
    assert judge("r", fx, {"a", "b"}, correlation=False) == []
    assert judge("r", fx, {"a"}, correlation=False) == ["r: positive/positive.jsonl: did not match b"]
    assert judge("r", fx, set(), correlation=False) == ["r: positive/positive.jsonl: did not match a, b"]


def test_judge_negative_must_be_silent(tmp_path: Path):
    fx = _fx(tmp_path, "negative", ["n1"])
    assert judge("r", fx, set(), correlation=False) == []
    assert judge("r", fx, {"n1"}, correlation=False) == ["r: negative/negative.jsonl: fired on n1"]


def test_judge_correlation_positive_needs_one_alert(tmp_path: Path):
    fx = _fx(tmp_path, "positive", ["a", "b", "c"])
    assert judge("r", fx, {"a"}, correlation=True) == []
    assert judge("r", fx, set(), correlation=True) == ["r: positive/positive.jsonl: no correlation alert"]
