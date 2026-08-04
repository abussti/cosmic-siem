"""
test_day51.py — Day 51 Multi-Tenant Data Isolation Layer

Mocked-ES test suite — safe to run anywhere, no live cluster needed. Same
convention as test_day46.py / test_day48.py / test_day49.py: patches
requests.get/post/put with an in-memory fake ES so isolation behavior can
be verified without the real stack. Run this against the real stack too
(python3 -m multi_tenant.tenant_manager, which runs _self_test() live)
once deployed to ~/elastic/langgraph/.
"""

import sys
import fnmatch
from unittest.mock import patch, MagicMock


# ── minimal fake Elasticsearch backend ─────────────────────────────────

class FakeES:
    def __init__(self):
        self.indices = {}   # index_name -> {doc_id: doc}
        self._counter = 0

    def put_index(self, index, body):
        self.indices.setdefault(index, {})
        return {"acknowledged": True}

    def index_doc(self, index, body, doc_id=None):
        self.indices.setdefault(index, {})
        if doc_id is None:
            self._counter += 1
            doc_id = f"auto_{self._counter}"
        self.indices[index][doc_id] = body
        return {"_id": doc_id, "result": "created"}

    def get_doc(self, index, doc_id):
        doc = self.indices.get(index, {}).get(doc_id)
        if doc is None:
            return {"found": False}
        return {"found": True, "_source": doc}

    def search(self, index_pattern, body):
        matched_indices = [idx for idx in self.indices if fnmatch.fnmatch(idx, index_pattern)]
        query = body.get("query", {})
        tenant_filter = None
        if "bool" in query:
            for f in query["bool"].get("filter", []):
                if "term" in f and "tenant_id" in f["term"]:
                    tenant_filter = f["term"]["tenant_id"]
        hits = []
        for idx in matched_indices:
            for doc_id, doc in self.indices[idx].items():
                if tenant_filter is not None and doc.get("tenant_id") != tenant_filter:
                    continue
                hits.append({"_id": doc_id, "_index": idx, "_source": doc})
        return {"hits": {"total": {"value": len(hits)}, "hits": hits}}


fake_es = FakeES()


def fake_requests_put(url, json=None, auth=None, timeout=None):
    path = url.split("/", 3)[-1]
    resp = MagicMock()
    resp.json.return_value = fake_es.put_index(path, json)
    return resp


def fake_requests_post(url, json=None, auth=None, timeout=None):
    path = url.split("/", 3)[-1]
    resp = MagicMock()
    if path.endswith("/_search"):
        index_pattern = path[: -len("/_search")]
        resp.json.return_value = fake_es.search(index_pattern, json)
    elif "/_doc" in path:
        index, rest = path.split("/_doc", 1)
        doc_id = rest[1:] if rest.startswith("/") else None
        resp.json.return_value = fake_es.index_doc(index, json, doc_id)
    else:
        resp.json.return_value = {"error": f"unhandled path {path}"}
    return resp


def fake_requests_get(url, auth=None, timeout=None):
    path = url.split("/", 3)[-1]
    resp = MagicMock()
    if "/_doc/" in path:
        index, doc_id = path.split("/_doc/", 1)
        resp.json.return_value = fake_es.get_doc(index, doc_id)
    else:
        resp.json.return_value = {"error": f"unhandled path {path}"}
    return resp


def run_tests():
    checks_passed = 0
    checks_total = 0

    with patch("requests.post", side_effect=fake_requests_post), \
         patch("requests.put", side_effect=fake_requests_put), \
         patch("requests.get", side_effect=fake_requests_get):

        from multi_tenant import tenant_manager as tm

        # 1 — create two tenants
        r1 = tm.create_tenant("tenant_alpha", "Alpha Corp", {"log_sources": ["wazuh"]})
        r2 = tm.create_tenant("tenant_beta", "Beta LLC", {"log_sources": ["wazuh"]})
        checks_total += 2
        checks_passed += int(r1["success"]) + int(r2["success"])
        print(f"[1] create_tenant alpha/beta: success={r1['success']}/{r2['success']}")

        # 2 — tenant_config persisted and readable
        cfg = tm.get_tenant_config("tenant_alpha")
        checks_total += 1
        ok = cfg is not None and cfg["tenant_id"] == "tenant_alpha"
        checks_passed += int(ok)
        print(f"[2] get_tenant_config round-trip: {ok}")

        # 3 — write alert for tenant_alpha only
        tm.write_tenant_doc("tenant_alpha", "alerts", {
            "rule": {"id": "5710", "level": 10}, "data": {"srcip": "203.0.113.77"}
        })
        print("[3] wrote 1 alert doc for tenant_alpha")

        # 4 — tenant_alpha sees its own doc
        alpha_res = tm.tenant_query("tenant_alpha", "alerts", {"query": {"match_all": {}}})
        alpha_hits = alpha_res["hits"]["total"]["value"]
        checks_total += 1
        checks_passed += int(alpha_hits == 1)
        print(f"[4] tenant_alpha sees its own alert: hits={alpha_hits} (expect 1)")

        # 5 — tenant_beta sees ZERO of tenant_alpha's data (the core isolation check)
        beta_res = tm.tenant_query("tenant_beta", "alerts", {"query": {"match_all": {}}})
        beta_hits = beta_res["hits"]["total"]["value"]
        checks_total += 1
        checks_passed += int(beta_hits == 0)
        print(f"[5] tenant_beta isolation check: hits={beta_hits} (expect 0)")

        # 6 — raw/unscoped query is blocked
        checks_total += 1
        try:
            tm.raw_query_blocked("alerts", {"query": {"match_all": {}}})
            print("[6] raw_query_blocked did NOT raise — FAIL")
        except tm.TenantIsolationError:
            checks_passed += 1
            print("[6] raw_query_blocked correctly raised TenantIsolationError")

        # 7 — tenant_query with no tenant_id is blocked
        checks_total += 1
        try:
            tm.tenant_query(None, "alerts", {"query": {"match_all": {}}})
            print("[7] tenant_query(None, ...) did NOT raise — FAIL")
        except tm.TenantIsolationError:
            checks_passed += 1
            print("[7] tenant_query(None, ...) correctly raised TenantIsolationError")

        # 8 — write_tenant_doc with no tenant_id is blocked
        checks_total += 1
        try:
            tm.write_tenant_doc(None, "alerts", {"foo": "bar"})
            print("[8] write_tenant_doc(None, ...) did NOT raise — FAIL")
        except tm.TenantIsolationError:
            checks_passed += 1
            print("[8] write_tenant_doc(None, ...) correctly raised TenantIsolationError")

        # 9 — invalid tenant_id rejected at registration
        checks_total += 1
        bad = tm.create_tenant("tenant alpha!!", "Bad Name")
        checks_passed += int(bad["success"] is False)
        print(f"[9] create_tenant rejects invalid tenant_id: success={bad['success']} (expect False)")

        # 10 — cross-family isolation: alpha's hunts index doesn't leak into alerts query
        tm.write_tenant_doc("tenant_alpha", "hunts", {"hunt_name": "test_hunt"})
        cross_res = tm.tenant_query("tenant_alpha", "alerts", {"query": {"match_all": {}}})
        checks_total += 1
        checks_passed += int(cross_res["hits"]["total"]["value"] == 1)  # still just the 1 alert doc
        print(f"[10] family isolation (hunts doc doesn't leak into alerts query): "
              f"hits={cross_res['hits']['total']['value']} (expect 1)")

    print(f"\n{checks_passed}/{checks_total} checks passed.")
    return checks_passed == checks_total


if __name__ == "__main__":
    ok = run_tests()
    sys.exit(0 if ok else 1)
