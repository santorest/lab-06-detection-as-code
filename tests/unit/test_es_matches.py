import json
from pathlib import Path

from common import Fixture
from es_matches import INDEX_BODY, bulk_body, ids_from_search, index_name, search_body


def test_index_body_lowercases_keyword_strings():
    """Sigma matching is case-insensitive; keyword fields must be normalised (Review Focus 1)."""
    assert INDEX_BODY["settings"]["analysis"]["normalizer"]["lc"]["filter"] == ["lowercase"]
    [tpl] = INDEX_BODY["mappings"]["dynamic_templates"]
    assert tpl["strings"]["match_mapping_type"] == "string"
    assert tpl["strings"]["mapping"] == {"type": "keyword", "normalizer": "lc"}


def test_index_name_is_lowercase_and_unique_per_file():
    fx = Fixture(Path("tests/events/Proc_X/positive/02-Mixed.jsonl"), "positive", [])
    assert index_name("Proc_X", fx) == "lab06-proc_x-positive-02-mixed"


def test_bulk_body_is_ndjson_with_trailing_newline():
    body = bulk_body("i1", [{"TestEventId": "a"}, {"TestEventId": "b"}])
    lines = body.split("\n")
    assert body.endswith("\n")
    assert json.loads(lines[0]) == {"index": {"_index": "i1"}}
    assert json.loads(lines[1]) == {"TestEventId": "a"}
    assert len([ln for ln in lines if ln]) == 4


def test_search_body():
    body = search_body("Image:*\\\\powershell.exe")
    assert body["query"]["query_string"]["query"] == "Image:*\\\\powershell.exe"
    assert body["query"]["query_string"]["analyze_wildcard"] is True
    assert body["_source"] == ["TestEventId"]
    assert body["size"] >= 100


def test_ids_from_search():
    resp = {"hits": {"hits": [{"_source": {"TestEventId": "a"}}, {"_source": {"TestEventId": "b"}}]}}
    assert ids_from_search(resp) == {"a", "b"}
    assert ids_from_search({"hits": {"hits": []}}) == set()
