"""Match engine 2: index each fixture file into Elasticsearch and run the rule's Lucene conversion."""

from __future__ import annotations

import argparse
import json
import sys
import time
import urllib.error
import urllib.request

from common import ROOT, Fixture, judge, load_fixtures, load_rules, load_support, load_targets
from convert import ConvertError, convert

# Every string is a keyword with a lowercase normalizer: Sigma matching is case-insensitive.
INDEX_BODY = {
    "settings": {
        "number_of_shards": 1,
        "number_of_replicas": 0,
        "analysis": {"normalizer": {"lc": {"type": "custom", "filter": ["lowercase"]}}},
    },
    "mappings": {
        "dynamic_templates": [
            {"strings": {"match_mapping_type": "string", "mapping": {"type": "keyword", "normalizer": "lc"}}}
        ]
    },
}


def index_name(slug: str, fixture: Fixture) -> str:
    return f"lab06-{slug}-{fixture.polarity}-{fixture.path.stem}".lower()


def bulk_body(index: str, events: list[dict]) -> str:
    lines = []
    for event in events:
        lines += [json.dumps({"index": {"_index": index}}), json.dumps(event)]
    return "\n".join(lines) + "\n"


def search_body(query: str) -> dict:
    return {
        "size": 1000,
        "_source": ["TestEventId"],
        "query": {"query_string": {"query": query, "analyze_wildcard": True}},
    }


def ids_from_search(resp: dict) -> set[str]:
    return {h["_source"]["TestEventId"] for h in resp["hits"]["hits"]}


class EsClient:
    def __init__(self, base_url: str) -> None:
        self.base = base_url.rstrip("/")

    def request(self, method: str, path: str, body: object = None, ndjson: bool = False) -> dict:
        data = None
        headers = {}
        if body is not None:
            data = (body if isinstance(body, str) else json.dumps(body)).encode()
            headers["Content-Type"] = "application/x-ndjson" if ndjson else "application/json"
        req = urllib.request.Request(self.base + path, data=data, method=method, headers=headers)
        try:
            with urllib.request.urlopen(req, timeout=30) as resp:
                return json.loads(resp.read() or b"{}")
        except urllib.error.HTTPError as exc:
            raise RuntimeError(f"{method} {path}: HTTP {exc.code}: {exc.read().decode()[:1000]}") from None

    def wait(self, timeout_s: int) -> None:
        deadline = time.monotonic() + timeout_s
        while True:
            try:
                health = self.request("GET", "/_cluster/health?wait_for_status=yellow&timeout=5s")
                if health.get("status") in ("yellow", "green"):
                    return
            except (OSError, RuntimeError):
                pass
            if time.monotonic() > deadline:
                raise RuntimeError(f"Elasticsearch not ready at {self.base} after {timeout_s}s")
            time.sleep(3)


def run_fixture(es: EsClient, slug: str, fx: Fixture, query: str) -> set[str]:
    index = index_name(slug, fx)
    es.request("DELETE", f"/{index}?ignore_unavailable=true")
    es.request("PUT", f"/{index}", INDEX_BODY)
    resp = es.request("POST", "/_bulk?refresh=true", bulk_body(index, fx.events), ndjson=True)
    if resp.get("errors"):
        raise RuntimeError(f"bulk indexing errors for {fx.path.name}: {json.dumps(resp)[:1000]}")
    try:
        return ids_from_search(es.request("POST", f"/{index}/_search", search_body(query)))
    finally:
        es.request("DELETE", f"/{index}")


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--url", default="http://localhost:9200")
    parser.add_argument("--wait", type=int, default=0, help="seconds to wait for the cluster")
    parser.add_argument("slugs", nargs="*")
    ns = parser.parse_args()
    es = EsClient(ns.url)
    if ns.wait:
        es.wait(ns.wait)
    targets = load_targets(ROOT / "targets.yaml")
    support = load_support(ROOT / "support.yaml")
    errors, checked = [], 0
    for rule in load_rules(ROOT / "rules"):
        if ns.slugs and rule.slug not in ns.slugs:
            continue
        args = targets[rule.platform]["es_lucene"]
        excl = support.get((rule.slug, "elasticsearch"))
        if excl:
            if excl.kind == "unsupported":
                try:
                    convert(rule, "lucene", args, ROOT)
                    errors.append(f"{rule.slug}: elasticsearch exclusion is stale (Lucene conversion now works)")
                except ConvertError:
                    pass
            print(f"SKIP {rule.slug}: {excl.reason}")
            continue
        try:
            query = convert(rule, "lucene", args, ROOT).strip()
        except ConvertError as exc:
            errors.append(f"{rule.slug}: lucene conversion failed: {exc}")
            continue
        rule_errors = []
        for fx in load_fixtures(ROOT / "tests" / "events", rule.slug):
            checked += 1
            try:
                rule_errors += judge(rule.slug, fx, run_fixture(es, rule.slug, fx, query), rule.is_correlation)
            except RuntimeError as exc:
                rule_errors.append(f"{rule.slug}: {fx.polarity}/{fx.path.name}: {exc}")
        print(f"{'FAIL' if rule_errors else 'ok  '} {rule.slug}")
        errors += rule_errors
    for e in errors:
        print(e)
    print(f"elasticsearch: {checked} fixture files, {len(errors)} failure(s)")
    return 1 if errors else 0


if __name__ == "__main__":
    sys.exit(main())
