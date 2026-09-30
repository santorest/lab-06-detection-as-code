from pathlib import Path

import pytest
from check_metadata import check_repo
from conftest import CORRELATION_RULE, VALID_RULE, write_events

RULE = "rules/windows/proc_creation_test_enc.yml"


def _set_rule(repo: Path, text: str) -> None:
    (repo / RULE).write_text(text, encoding="utf-8")


def test_valid_repo_passes(repo: Path):
    assert check_repo(repo) == []


@pytest.mark.parametrize(
    ("old", "new", "message"),
    [
        ("id: 11111111-1111-4111-8111-111111111111", "id: not-a-uuid", "id is not a UUID"),
        ("status: test", "status: draft", "status"),
        ("description: Test rule.", "description: ''", "description"),
        ("author: Test Author", "author: ''", "author"),
        ("date: 2026-09-30", "date: yesterday", "date"),
        ("level: medium", "level: severe", "level"),
        ("  - Admin scripts", "  - ''", "falsepositives"),
        ("  - attack.t1059.001", "  - attack.s0001", "ATT&CK technique tag"),
        ("  - attack.execution", "  - attack.executing", "ATT&CK tactic tag"),
        ("references:\n  - https://attack.mitre.org/techniques/T1059/001/", "references: []", "references"),
    ],
)
def test_metadata_errors(repo: Path, old: str, new: str, message: str):
    assert old in VALID_RULE
    _set_rule(repo, VALID_RULE.replace(old, new))
    errors = check_repo(repo)
    assert any(message in e and "proc_creation_test_enc" in e for e in errors), errors


@pytest.mark.parametrize(
    ("tactic", "ok"), [("stealth", True), ("defense-impairment", True), ("defense-evasion", False)]
)
def test_tactics_follow_attack_v19(repo: Path, tactic: str, ok: bool):
    """ATT&CK v19 split Defense Evasion into Stealth and Defense Impairment."""
    _set_rule(repo, VALID_RULE.replace("  - attack.execution", f"  - attack.{tactic}"))
    assert (check_repo(repo) == []) is ok


def test_duplicate_ids_across_rules(repo: Path):
    (repo / "rules/windows/proc_creation_test_dup.yml").write_text(VALID_RULE, encoding="utf-8")
    ev = repo / "tests/events/proc_creation_test_dup"
    write_events(ev / "positive/01.jsonl", [{"TestEventId": "p1"}])
    write_events(ev / "negative/01.jsonl", [{"TestEventId": "n1"}])
    assert any("duplicate id" in e for e in check_repo(repo))


def test_unexpected_files_under_rules(repo: Path):
    (repo / "rules/windows/notes.txt").write_text("x", encoding="utf-8")
    (repo / "rules/macos").mkdir()
    (repo / "rules/macos/r.yml").write_text(VALID_RULE, encoding="utf-8")
    errors = check_repo(repo)
    assert sum("unexpected file" in e for e in errors) == 2


@pytest.mark.parametrize("polarity", ["positive", "negative"])
def test_missing_fixture_folder(repo: Path, polarity: str):
    for f in (repo / f"tests/events/proc_creation_test_enc/{polarity}").iterdir():
        f.unlink()
    assert any(f"no {polarity} fixtures" in e for e in check_repo(repo))


def test_malformed_fixture_reported_with_line(repo: Path):
    (repo / "tests/events/proc_creation_test_enc/negative/02.jsonl").write_text("{bad\n", encoding="utf-8")
    assert any("02.jsonl:1: invalid JSON" in e for e in check_repo(repo))


def test_duplicate_test_event_id(repo: Path):
    write_events(repo / "tests/events/proc_creation_test_enc/negative/02.jsonl", [{"TestEventId": "p1"}])
    assert any("duplicate TestEventId p1" in e for e in check_repo(repo))


def test_orphan_fixture_dir(repo: Path):
    write_events(repo / "tests/events/gone_rule/positive/01.jsonl", [{"TestEventId": "x"}])
    assert any("orphan fixtures" in e and "gone_rule" in e for e in check_repo(repo))


def test_correlation_names_must_resolve(repo: Path):
    (repo / "rules/azure").mkdir()
    (repo / "rules/azure/activity_mass_test.yml").write_text(
        CORRELATION_RULE.replace("    - base_delete", "    - other_name"), encoding="utf-8"
    )
    ev = repo / "tests/events/activity_mass_test"
    write_events(ev / "positive/01.jsonl", [{"TestEventId": "a"}])
    write_events(ev / "negative/01.jsonl", [{"TestEventId": "b"}])
    assert any("unknown rule name other_name" in e for e in check_repo(repo))


def test_support_yaml_unknown_rule(repo: Path):
    (repo / "support.yaml").write_text(
        "exclusions:\n  - rule: nope\n    targets: [lucene]\n    kind: unsupported\n    reason: x\n", encoding="utf-8"
    )
    assert any("support.yaml" in e and "nope" in e for e in check_repo(repo))
