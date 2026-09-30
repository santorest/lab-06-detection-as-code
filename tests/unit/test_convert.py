from pathlib import Path

import pytest
from common import load_rules
from convert import ConvertError, check, convert, normalize


def test_normalize_line_endings_and_trailing_space():
    assert normalize("a  \r\nb\r\n\r\n") == "a\nb\n"
    assert normalize("﻿q\n") == "q\n"


def _targets(repo: Path) -> None:
    (repo / "targets.yaml").write_text(
        "windows:\n  convert:\n    splunk: [-p, splunk_windows]\n    lucene: [-p, ecs_windows]\n", encoding="utf-8"
    )


def _ok(rule, backend, args, root):
    return f"{backend}:{rule.slug}\n"


def _fails(rule, backend, args, root):
    raise ConvertError("unsupported feature")


def test_update_then_check_is_clean(repo: Path):
    _targets(repo)
    assert check(repo, ["splunk", "lucene"], update=True, run=_ok) == []
    golden = repo / "tests/expected/splunk/proc_creation_test_enc.txt"
    assert golden.read_text(encoding="utf-8") == "splunk:proc_creation_test_enc\n"
    assert check(repo, ["splunk", "lucene"], update=False, run=_ok) == []


def test_missing_and_mismatched_golden(repo: Path):
    _targets(repo)
    assert any("missing golden" in e for e in check(repo, ["splunk"], update=False, run=_ok))
    check(repo, ["splunk"], update=True, run=_ok)
    (repo / "tests/expected/splunk/proc_creation_test_enc.txt").write_text("old\n", encoding="utf-8")
    assert any("golden mismatch" in e for e in check(repo, ["splunk"], update=False, run=_ok))


def test_unlisted_conversion_failure_is_error(repo: Path):
    _targets(repo)
    errors = check(repo, ["splunk"], update=True, run=_fails)
    assert any("conversion failed" in e and "unsupported feature" in e for e in errors)


def _exclude(repo: Path, kind: str) -> None:
    (repo / "support.yaml").write_text(
        f"exclusions:\n  - rule: proc_creation_test_enc\n    targets: [splunk]\n    kind: {kind}\n    reason: x\n",
        encoding="utf-8",
    )


def test_unsupported_exclusion_passes_when_conversion_fails(repo: Path):
    _targets(repo)
    _exclude(repo, "unsupported")
    assert check(repo, ["splunk"], update=False, run=_fails) == []


def test_stale_unsupported_exclusion_is_error(repo: Path):
    _targets(repo)
    _exclude(repo, "unsupported")
    assert any("exclusion is stale" in e for e in check(repo, ["splunk"], update=False, run=_ok))


def test_not_applicable_is_skipped_but_golden_forbidden(repo: Path):
    _targets(repo)
    _exclude(repo, "not-applicable")
    assert check(repo, ["splunk"], update=False, run=_fails) == []
    p = repo / "tests/expected/splunk/proc_creation_test_enc.txt"
    p.parent.mkdir(parents=True)
    p.write_text("x\n", encoding="utf-8")
    assert any("golden file exists for excluded pair" in e for e in check(repo, ["splunk"], update=False, run=_fails))


def test_missing_targets_args(repo: Path):
    _targets(repo)
    assert any("no targets.yaml args" in e for e in check(repo, ["kusto"], update=False, run=_ok))


def test_orphan_golden(repo: Path):
    _targets(repo)
    check(repo, ["splunk"], update=True, run=_ok)
    orphan = repo / "tests/expected/splunk/deleted_rule.txt"
    orphan.write_text("x\n", encoding="utf-8")
    assert any("orphan golden" in e for e in check(repo, ["splunk"], update=False, run=_ok))
    check(repo, ["splunk"], update=True, run=_ok)
    assert not orphan.exists()


def test_real_sigma_convert_smoke(repo: Path):
    """One real sigma-cli call so the subprocess wiring is covered."""
    [rule] = load_rules(repo / "rules")
    assert "CommandLine" in convert(rule, "splunk", ["-p", "splunk_windows"], repo)


def test_real_sigma_convert_failure_reports_the_error_line(repo: Path):
    """The message is sigma-cli's `Error:` line, not the help text that follows it."""
    [rule] = load_rules(repo / "rules")
    with pytest.raises(ConvertError) as info:
        convert(rule, "splunk", ["-p", "no_such_pipeline"], repo)
    assert str(info.value) == "The pipeline 'no_such_pipeline' was not found."
