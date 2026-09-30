import json
from pathlib import Path

import pytest
from attack_coverage import END, START, navigator_layer, render_table, replace_block, run
from common import Exclusion, load_rules
from conftest import VALID_RULE


def test_render_table(repo: Path):
    rules = load_rules(repo / "rules")
    table = render_table(rules, {("proc_creation_test_enc", "kusto"): Exclusion("unsupported", "x")})
    assert "**1 rules · 1 techniques · 1 tactics**" in table
    assert "[T1059.001](https://attack.mitre.org/techniques/T1059/001/)" in table
    assert "| Execution |" in table
    assert "Test encoded command" in table
    assert "kusto" in table


def test_gaps_are_listed_per_rule(repo: Path):
    """Two rules share a technique; only one has a gap, so the gap must not be attributed to both."""
    other = VALID_RULE.replace("11111111-1111-4111-8111-111111111111", "44444444-4444-4444-8444-444444444444")
    (repo / "rules/windows/proc_creation_test_other.yml").write_text(
        other.replace("Test encoded command", "Other rule"), encoding="utf-8"
    )
    table = render_table(load_rules(repo / "rules"), {("proc_creation_test_other", "kusto"): Exclusion("x", "y")})
    assert "| Test encoded command<br>Other rule | —<br>kusto |" in table


def test_render_table_tactic_names(repo: Path):
    (repo / "rules/windows/proc_creation_test_enc.yml").write_text(
        (repo / "rules/windows/proc_creation_test_enc.yml")
        .read_text(encoding="utf-8")
        .replace("  - attack.execution", "  - attack.defense-impairment"),
        encoding="utf-8",
    )
    assert "| Defense Impairment |" in render_table(load_rules(repo / "rules"), {})


def test_navigator_layer(repo: Path):
    layer = navigator_layer(load_rules(repo / "rules"))
    assert layer["domain"] == "enterprise-attack"
    assert layer["techniques"] == [{"techniqueID": "T1059.001", "score": 1, "comment": "Test encoded command"}]


def test_replace_block():
    text = f"intro\n{START}\nold\n{END}\nend\n"
    assert replace_block(text, "new") == f"intro\n{START}\nnew\n{END}\nend\n"
    with pytest.raises(ValueError):
        replace_block("no markers", "new")


def test_run_check_detects_stale_readme(repo: Path):
    (repo / "README.md").write_text(f"# x\n{START}\nstale\n{END}\n", encoding="utf-8")
    assert run(repo, check=True) != []
    assert run(repo, check=False) == []
    assert run(repo, check=True) == []
    assert json.loads((repo / "coverage/attack-navigator.json").read_text(encoding="utf-8"))["techniques"]
