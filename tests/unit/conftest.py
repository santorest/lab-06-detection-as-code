import json
import textwrap
from pathlib import Path

import pytest

VALID_RULE = textwrap.dedent("""\
    title: Test encoded command
    id: 11111111-1111-4111-8111-111111111111
    status: test
    description: Test rule.
    references:
      - https://attack.mitre.org/techniques/T1059/001/
    author: Test Author
    date: 2026-09-30
    tags:
      - attack.execution
      - attack.t1059.001
    logsource:
      category: process_creation
      product: windows
    detection:
      selection:
        CommandLine|contains: ' -enc '
      condition: selection
    falsepositives:
      - Admin scripts
    level: medium
    """)

CORRELATION_RULE = textwrap.dedent("""\
    title: Base delete
    id: 22222222-2222-4222-8222-222222222222
    name: base_delete
    status: test
    logsource:
      product: azure
      service: activitylogs
    detection:
      selection:
        operationName|endswith: /DELETE
      condition: selection
    ---
    title: Mass delete
    id: 33333333-3333-4333-8333-333333333333
    status: test
    description: Many deletes.
    references:
      - https://attack.mitre.org/techniques/T1485/
    author: Test Author
    date: 2026-09-30
    tags:
      - attack.impact
      - attack.t1485
    correlation:
      type: event_count
      rules:
        - base_delete
      group-by:
        - caller
      timespan: 15m
      condition:
        gte: 10
    falsepositives:
      - Cleanup
    level: high
    """)


def write_events(path: Path, events: list[dict]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text("".join(json.dumps(e) + "\n" for e in events), encoding="utf-8")


@pytest.fixture
def repo(tmp_path: Path) -> Path:
    """A minimal valid repo: one windows rule with one positive and one negative fixture."""
    (tmp_path / "rules" / "windows").mkdir(parents=True)
    (tmp_path / "rules" / "windows" / "proc_creation_test_enc.yml").write_text(VALID_RULE, encoding="utf-8")
    ev = tmp_path / "tests" / "events" / "proc_creation_test_enc"
    write_events(ev / "positive" / "01.jsonl", [{"TestEventId": "p1", "CommandLine": "x -enc AAA"}])
    write_events(ev / "negative" / "01.jsonl", [{"TestEventId": "n1", "CommandLine": "x -File a.ps1"}])
    (tmp_path / "support.yaml").write_text("exclusions: []\n", encoding="utf-8")
    return tmp_path
