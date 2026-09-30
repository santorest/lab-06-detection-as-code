import json
import sys
from pathlib import Path

import pytest
from check_matches import ZircoliteError, matched_ids, run_zircolite


def test_matched_ids_plain_matches():
    results = [{"title": "r", "matches": [{"row_id": 1, "TestEventId": "p1"}, {"row_id": 2, "TestEventId": "p2"}]}]
    assert matched_ids(results) == {"p1", "p2"}


def test_matched_ids_correlation_evidence():
    results = [
        {
            "title": "c",
            "matches": [
                {
                    "result_type": "correlation",
                    "evidence": [{"event": {"TestEventId": "a"}}, {"event": {"TestEventId": "b"}}],
                }
            ],
        }
    ]
    assert matched_ids(results) == {"a", "b"}


def test_matched_ids_empty():
    assert matched_ids([]) == set()


def _fake_exe(tmp_path: Path, body: str) -> Path:
    """A stand-in for Zircolite: a Python script behind a platform launcher."""
    script = tmp_path / "fake.py"
    script.write_text(body, encoding="utf-8")
    if sys.platform == "win32":
        exe = tmp_path / "fake.cmd"
        exe.write_text(f'@"{sys.executable}" "{script}" %*\n', encoding="utf-8")
    else:
        exe = tmp_path / "fake.sh"
        exe.write_text(f'#!/bin/sh\nexec "{sys.executable}" "{script}" "$@"\n', encoding="utf-8")
        exe.chmod(0o755)
    return exe


WRITES_OUTPUT = """import json, sys
out = sys.argv[sys.argv.index("-o") + 1]
json.dump([{"title": "r", "matches": [{"TestEventId": "p1"}]}], open(out, "w"))
"""


def test_run_zircolite_reads_output(tmp_path: Path):
    exe = _fake_exe(tmp_path, WRITES_OUTPUT)
    assert matched_ids(run_zircolite(exe, tmp_path / "r.yml", tmp_path / "e.jsonl", [], tmp_path)) == {"p1"}


def test_run_zircolite_nonzero_exit_is_error(tmp_path: Path):
    exe = _fake_exe(tmp_path, "import sys; sys.stderr.write('boom'); sys.exit(2)\n")
    with pytest.raises(ZircoliteError, match="exit 2"):
        run_zircolite(exe, tmp_path / "r.yml", tmp_path / "e.jsonl", [], tmp_path)


def test_run_zircolite_non_ascii_output_is_reported(tmp_path: Path):
    """Zircolite prints UTF-8 (emoji, box drawing); decoding must not depend on the console code page."""
    # U+2590 and U+0081 encode to bytes (0x90, 0x81) that cp1252 cannot decode, as in a real Zircolite run.
    exe = _fake_exe(tmp_path, "import sys; sys.stdout.buffer.write('\\u2590 \\x81'.encode()); sys.exit(3)\n")
    with pytest.raises(ZircoliteError, match="exit 3"):
        run_zircolite(exe, tmp_path / "r.yml", tmp_path / "e.jsonl", [], tmp_path)


def test_run_zircolite_missing_output_is_error(tmp_path: Path):
    exe = _fake_exe(tmp_path, "pass\n")
    with pytest.raises(ZircoliteError, match="no output file"):
        run_zircolite(exe, tmp_path / "r.yml", tmp_path / "e.jsonl", [], tmp_path)


def test_run_zircolite_invalid_output_is_error(tmp_path: Path):
    exe = _fake_exe(tmp_path, "import sys; open(sys.argv[sys.argv.index('-o') + 1], 'w').write('not json')\n")
    with pytest.raises(ZircoliteError, match="unreadable output"):
        run_zircolite(exe, tmp_path / "r.yml", tmp_path / "e.jsonl", [], tmp_path)


def test_stale_output_file_is_not_reused(tmp_path: Path):
    (tmp_path / "detected.json").write_text(json.dumps([{"matches": [{"TestEventId": "old"}]}]), encoding="utf-8")
    exe = _fake_exe(tmp_path, "pass\n")
    with pytest.raises(ZircoliteError, match="no output file"):
        run_zircolite(exe, tmp_path / "r.yml", tmp_path / "e.jsonl", [], tmp_path)


def test_matched_ids_counts_a_match_without_test_event_id():
    """An alert that cannot be traced to a fixture event must not read as 'no matches' (a negative would pass)."""
    results = [{"title": "r", "matches": [{"row_id": 1}]}]
    assert matched_ids(results) == {"<unidentified match of r>"}


def test_matched_ids_counts_a_correlation_alert_without_evidence():
    results = [{"title": "c", "matches": [{"result_type": "correlation", "alert_id": "a1", "evidence": []}]}]
    assert matched_ids(results) == {"<unidentified match of c>"}
