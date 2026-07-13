# How To Add a New Hunt Playbook

This covers the **production** hunting engine — `tools/hunt_loader.py` — which drives the
6 registered YAML hunts (Hunts 1-5, plus 2b). If you're not sure which engine you're in,
read `PHASE2-ARCHITECTURE.md` section 3 first — there are two, and this is the one you want.

New hunts are added as **data (YAML), not code**. `hunt_loader.py` does not need to change.

---

## 1. Where playbooks live

```
~/elastic/langgraph/hunts/*.yml
```

Every `.yml` file in this directory is loaded automatically by `load_hunt_playbooks()` and run
every cycle by `run_all_yaml_hunts()`. There is no separate registration step or import list —
dropping a valid file in is enough.

## 2. Required fields

Every playbook YAML must have these top-level keys (`REQUIRED_FIELDS` in `hunt_loader.py`):

| Field | Type | Purpose |
|---|---|---|
| `hunt_name` | string | Unique identifier, used as the ES `hunt_name` in `siem-hunt-results` |
| `hypothesis` | string | Plain-English description of what you're hunting for — shown to the LLM summarizer |
| `elastic_query` | Elastic DSL | The query/aggregation body (see shapes below) |
| `finding_threshold` | integer | Hit/bucket count needed to count as a "threat found" |
| `mitre_technique` | string | MITRE ATT&CK ID, e.g. `T1071` |
| `escalate_if_found` | boolean | Whether crossing `finding_threshold` triggers escalation to triage |

Loading fails loudly (not silently) if any field is missing — check `load_hunt_playbooks()`'s
validation error message, it names the missing field and file.

## 3. Two query shapes

`hunt_loader.py` handles both generically:

- **Hit-based** (e.g. Hunt 3, LOLBins): a plain query, `finding_threshold` checked in Python
  against the number of matching documents.
- **Aggregation-based** (e.g. Hunt 1, lateral movement; Hunt 5, beaconing): a `bucket_selector`
  or `cardinality` aggregation where the threshold is enforced **server-side in the query
  itself** — keep `finding_threshold` in the YAML in sync with whatever number is hardcoded
  into the aggregation's `bucket_selector.script`, since `_render_query()` substitutes the YAML
  value in at render time rather than requiring you to hand-edit the DSL twice.

## 4. Minimal example — hit-based hunt

```yaml
# hunts/hunt_new_process.yml
hunt_name: rare_process_execution
hypothesis: >
  Flags execution of a process name never seen before on that host in the last 30 days —
  a common signal for a dropped/renamed malicious binary.
mitre_technique: T1036
finding_threshold: 1
escalate_if_found: true
elastic_query:
  bool:
    must:
      - term: { rule.groups: "process_execution" }
    filter:
      - range: { "@timestamp": { gte: "now-{{TIME_WINDOW_HOURS}}h" } }
time_window_hours: 6
```

`{{TIME_WINDOW_HOURS}}` is substituted from the top-level `time_window_hours` field by
`_render_query()` — always use the placeholder rather than hardcoding the number twice.

## 5. Minimal example — aggregation-based hunt with a baseline check

Only add `baseline_check` if a matching baseline actually exists in `siem-baselines`
(see `tools/baseline_builder.py` for what's currently built: `login_count_per_day`,
`outbound_conn_per_hour`). Otherwise every finding gets tagged `baseline_status:
"no_baseline_yet"` and the enrichment is a no-op.

```yaml
hunt_name: unusual_login_volume
hypothesis: >
  Flags users whose daily login count is more than 3x their 7-day baseline —
  possible credential compromise / automated access.
mitre_technique: T1078
finding_threshold: 1
escalate_if_found: true
time_window_hours: 24
baseline_check:
  baseline_type: login_count_per_day
  entity_field: data.dstuser
  multiplier: 3
elastic_query:
  bool:
    must:
      - term: { rule.groups: "authentication_success" }
    filter:
      - range: { "@timestamp": { gte: "now-{{TIME_WINDOW_HOURS}}h" } }
  aggs:
    by_user:
      terms: { field: "data.dstuser", size: 100 }
```

## 6. Test before registering it for real

Don't just drop the file and wait for the 6-hour scheduler. Every hunt should be smoke-tested
the same way Hunts 1-5 were on Day 27-28:

```bash
# Verify it loads and validates
cd ~/elastic/langgraph && python3 -c "
from tools.hunt_loader import load_hunt_playbooks
for p in load_hunt_playbooks():
    print(p['hunt_name'])
"

# Run just your new hunt
cd ~/elastic/langgraph && python3 -c "
from tools.hunt_loader import load_hunt_playbooks, run_yaml_hunt
playbooks = {p['hunt_name']: p for p in load_hunt_playbooks()}
result = run_yaml_hunt(playbooks['rare_process_execution'])
import json; print(json.dumps(result, indent=2, default=str))
"
```

Before trusting a non-zero result, cross-check it against a raw `curl` count for the same
query/window — this is exactly how the Day 26/28 "0 results" cases were confirmed correct
rather than silently broken. See `project.md`'s Day 26/28 sections for the pattern.

If your hunt uses `escalate_if_found: true`, also confirm (as of the Day 39 fix) that it:
1. Writes an entry to `siem-hunt-results` on every run, including zero-finding runs.
2. Calls `escalate_hunt_to_triage()` automatically when the threshold is crossed — you should
   **not** need to call this by hand anymore (that was the Day 39 bug fix).

## 7. Checklist before merging a new hunt

- [ ] YAML has all 6 required fields
- [ ] `time_window_hours` used via `{{TIME_WINDOW_HOURS}}`, not hardcoded twice
- [ ] `finding_threshold` matches whatever's baked into a `bucket_selector`, if aggregation-based
- [ ] Ran standalone, cross-checked hit count against raw ES `_count`
- [ ] If `escalate_if_found: true` — confirmed a synthetic true-positive event escalates end to
      end (writes to `siem-hunt-results`, reaches `coordination_agent`/triage)
- [ ] `agent.name` / `data.srcip` populate correctly in the resulting synthetic alert — check
      against the Day 39 fix to `build_synthetic_alert_from_hunt()`; if your finding's `key`
      shape doesn't match the existing `host`/`peer_ip`/`srcip` field names, extend that
      function rather than hardcoding a workaround in your hunt.
