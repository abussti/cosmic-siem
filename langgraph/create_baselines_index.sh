#!/bin/bash
# Day 28 — create siem-baselines index with explicit mapping.
# Run once before tools/baseline_builder.py.

curl -s -u elastic:changeme -X PUT http://localhost:9201/siem-baselines \
  -H "Content-Type: application/json" \
  -d '{
    "mappings": {
      "properties": {
        "baseline_type":   {"type": "keyword"},
        "entity":          {"type": "keyword"},
        "avg_count":       {"type": "float"},
        "raw_total_count": {"type": "integer"},
        "sample_days":     {"type": "integer"},
        "computed_at":     {"type": "date"}
      }
    }
  }' | python3 -m json.tool
