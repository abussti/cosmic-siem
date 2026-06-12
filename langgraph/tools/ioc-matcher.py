"""
ioc_matcher.py — Day 22
Queries the siem-threat-intel index for exact IOC matches.
Supports ioc_type: ip, domain, hash, url
"""

import requests
from requests.auth import HTTPBasicAuth

ES_URL  = "http://localhost:9201"
ES_AUTH = HTTPBasicAuth("elastic", "changeme")
INDEX   = "siem-threat-intel"

EMPTY_RESULT = {
    "matched":      False,
    "threat_actor": None,
    "campaign":     None,
    "confidence":   0,
    "source":       None,
}

VALID_TYPES = {"ip", "domain", "hash", "url"}


def match_ioc(value: str, ioc_type: str) -> dict:
    """
    Check a single indicator against the siem-threat-intel index.

    Args:
        value:    The raw indicator string (e.g. "1.2.3.4", "evil.com", "<sha256>")
        ioc_type: One of: ip | domain | hash | url

    Returns:
        {
            'matched':      bool,
            'threat_actor': str | None,
            'campaign':     str | None,   # not in current index — always None
            'confidence':   int,
            'source':       str | None,
        }
    """
    if not value or not value.strip():
        return {**EMPTY_RESULT}

    if ioc_type not in VALID_TYPES:
        raise ValueError(f"ioc_type must be one of {VALID_TYPES}, got: {ioc_type!r}")

    query = {
        "size": 1,
        "_source": ["ioc_type", "ioc_value", "threat_actor", "confidence", "source", "tags"],
        "query": {
            "bool": {
                "must": [
                    {"term": {"ioc_value": value.strip().lower() if ioc_type in ("ip", "domain") else value.strip()}},
                    {"term": {"ioc_type": ioc_type}},
                ]
            }
        },
    }

    try:
        resp = requests.post(
            f"{ES_URL}/{INDEX}/_search",
            auth=ES_AUTH,
            json=query,
            timeout=10,
        )
        resp.raise_for_status()
        data = resp.json()
    except requests.RequestException as e:
        print(f"[ioc_matcher] ES query failed: {e}")
        return {**EMPTY_RESULT}

    hits = data.get("hits", {}).get("hits", [])
    if not hits:
        return {**EMPTY_RESULT}

    src = hits[0]["_source"]
    return {
        "matched":      True,
        "threat_actor": src.get("threat_actor") or "unknown",
        "campaign":     None,   # not stored in current index schema
        "confidence":   src.get("confidence", 0),
        "source":       src.get("source"),
    }


def match_alert_iocs(alert: dict) -> list[dict]:
    """
    Convenience wrapper: extracts all IOC fields from a Wazuh alert dict
    and runs match_ioc() on each.

    Checks:
        data.srcip   → ip
        data.domain  → domain (if present)
        data.md5     → hash   (if present)
        data.sha256  → hash   (if present)

    Returns a list of match result dicts (only matched ones, empty list if none).
    """
    candidates = []

    src_ip = alert.get("data", {}).get("srcip")
    if src_ip and src_ip not in ("127.0.0.1", "::1"):
        candidates.append((src_ip, "ip"))

    domain = alert.get("data", {}).get("domain")
    if domain:
        candidates.append((domain, "domain"))

    for hash_field in ("md5", "sha256", "sha1"):
        h = alert.get("data", {}).get(hash_field)
        if h:
            candidates.append((h, "hash"))

    results = []
    for value, ioc_type in candidates:
        result = match_ioc(value, ioc_type)
        if result["matched"]:
            result["ioc_value"] = value
            result["ioc_type"]  = ioc_type
            results.append(result)

    return results


# ── self-test ────────────────────────────────────────────────────────────────

if __name__ == "__main__":
    import json

    # Pull a real malicious IP and domain from the index to use as known-bad values
    print("=" * 60)
    print("ioc_matcher.py — Day 22 self-test")
    print("=" * 60)

    # Fetch one real IP IOC and one real domain IOC from the index
    def _fetch_sample(ioc_type: str) -> str | None:
        r = requests.post(
            f"{ES_URL}/{INDEX}/_search",
            auth=ES_AUTH,
            json={
                "size": 1,
                "query": {"term": {"ioc_type": ioc_type}},
                "_source": ["ioc_value"],
            },
            timeout=10,
        )
        hits = r.json().get("hits", {}).get("hits", [])
        return hits[0]["_source"]["ioc_value"] if hits else None

    sample_ip     = _fetch_sample("ip")
    sample_domain = _fetch_sample("domain")
    sample_url    = _fetch_sample("url")
    sample_hash   = _fetch_sample("hash")

    tests = []

    # Test 1 — known malicious IP (from index)
    if sample_ip:
        r = match_ioc(sample_ip, "ip")
        tests.append({"test": "known_malicious_ip", "input": sample_ip, "result": r})
        status = "✓ PASS" if r["matched"] else "✗ FAIL"
        print(f"\n[1] Known malicious IP: {sample_ip}")
        print(f"    matched={r['matched']} | confidence={r['confidence']} | source={r['source']} → {status}")

    # Test 2 — known malicious domain (from index)
    if sample_domain:
        r = match_ioc(sample_domain, "domain")
        tests.append({"test": "known_malicious_domain", "input": sample_domain, "result": r})
        status = "✓ PASS" if r["matched"] else "✗ FAIL"
        print(f"\n[2] Known malicious domain: {sample_domain}")
        print(f"    matched={r['matched']} | confidence={r['confidence']} | source={r['source']} → {status}")

    # Test 3 — clean/private IP (should NOT match)
    r = match_ioc("192.168.1.1", "ip")
    tests.append({"test": "clean_private_ip", "input": "192.168.1.1", "result": r})
    status = "✓ PASS" if not r["matched"] else "✗ FAIL"
    print(f"\n[3] Clean private IP: 192.168.1.1")
    print(f"    matched={r['matched']} → {status}")

    # Test 4 — clean domain (should NOT match)
    r = match_ioc("google.com", "domain")
    tests.append({"test": "clean_domain", "input": "google.com", "result": r})
    status = "✓ PASS" if not r["matched"] else "✗ FAIL"
    print(f"\n[4] Clean domain: google.com")
    print(f"    matched={r['matched']} → {status}")

    # Test 5 — known URL or hash if available, else second clean IP
    if sample_url:
        r = match_ioc(sample_url, "url")
        tests.append({"test": "known_malicious_url", "input": sample_url, "result": r})
        status = "✓ PASS" if r["matched"] else "✗ FAIL"
        print(f"\n[5] Known malicious URL: {sample_url[:60]}...")
        print(f"    matched={r['matched']} | confidence={r['confidence']} | source={r['source']} → {status}")
    elif sample_hash:
        r = match_ioc(sample_hash, "hash")
        tests.append({"test": "known_malicious_hash", "input": sample_hash, "result": r})
        status = "✓ PASS" if r["matched"] else "✗ FAIL"
        print(f"\n[5] Known malicious hash: {sample_hash[:20]}...")
        print(f"    matched={r['matched']} | confidence={r['confidence']} | source={r['source']} → {status}")
    else:
        r = match_ioc("10.0.0.1", "ip")
        tests.append({"test": "clean_internal_ip_2", "input": "10.0.0.1", "result": r})
        status = "✓ PASS" if not r["matched"] else "✗ FAIL"
        print(f"\n[5] Clean internal IP: 10.0.0.1")
        print(f"    matched={r['matched']} → {status}")

    # Write results to docs/
    import os
    os.makedirs(os.path.expanduser("~/elastic/docs"), exist_ok=True)
    out_path = os.path.expanduser("~/elastic/docs/ioc-match-test.json")
    with open(out_path, "w") as f:
        json.dump(tests, f, indent=2)

    print(f"\n{'=' * 60}")
    print(f"Results written → {out_path}")
    passed = sum(
        1 for t in tests
        if (t["result"]["matched"] and "clean" not in t["test"])
        or (not t["result"]["matched"] and "clean" in t["test"])
    )
    print(f"Score: {passed}/{len(tests)} tests passed")
    print("=" * 60)
