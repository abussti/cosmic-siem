# How To Add a New Automated Response Action Safely

This covers adding a new action alongside `block_ip`/`isolate_endpoint` (Day 32/33) — e.g.
`disable_account_iam` or `create_ticket` (both still open, Phase 3 backlog).

Response actions are the highest-blast-radius part of this system — a bug here can disconnect
a real user or lock down a real host. Follow every step; don't skip the dry-run stage.

---

## 1. Design checklist before writing any code

- **Is it reversible?** Every existing action (`block_ip`/`unblock_ip`,
  `isolate_endpoint`/`unisolate_endpoint`) has a paired undo function. If your action can't be
  cleanly undone (e.g. deleting a resource), it should require human approval, full stop — do
  not wire it into automatic execution.
- **What does "success" actually mean?** Day 32 found that Wazuh's API returns HTTP 200 even
  when the underlying active-response command never reached the agent. Don't trust a 2xx status
  code alone — check the response body for the tool-specific equivalent of `total_failed_items`.
- **Does the underlying platform have a "delete"/reverse API path?** Day 32/33 both found Wazuh
  has no API-level reversal for stateful active-response scripts (confirmed against
  wazuh/wazuh#12342) — reversal had to go over direct SSH instead. Check this *before* writing
  the "add" path, since it changes your function signature (you may need SSH creds as well as
  API creds).

## 2. Where the code goes

`tools/response_tools.py` — one function pair per action, following the existing pattern:

```python
def new_action(target: str, endpoint: str) -> dict:
    """Executes <action>. Always returns a result dict, never raises."""
    try:
        # ... call the underlying API/script ...
        result = {"success": True, "action_type": "new_action", "target": target,
                  "endpoint": endpoint, "reversible": True, "detail": {...}}
    except Exception as e:
        result = {"success": False, "action_type": "new_action", "target": target,
                  "endpoint": endpoint, "reversible": True, "detail": str(e)}
    _log_response_action(result)   # existing helper — writes to siem-response-log
    return result

def undo_new_action(target: str, endpoint: str) -> dict:
    """Reverses new_action. Same contract."""
    ...
```

**Non-negotiable:** every call — success or failure — goes through `_log_response_action()` (or
your own equivalent that writes to `siem-response-log`). Day 32/33's audit trail specifically
depends on failed attempts being visible, not just successes; Scenario 3's Day 38 test relied on
exactly this to confirm a failed manual block was still logged correctly.

## 3. Wire it into the dispatch table — but keep it gated

In `agents/response_agent.py`, add to `ACTION_DISPATCH` (added Day 39 alongside the
`block_ip`/`isolate_endpoint` wiring):

```python
ACTION_DISPATCH = {
    "block_ip": lambda target, endpoint: block_ip(target, endpoint),
    "isolate_endpoint": lambda target, endpoint: isolate_endpoint(endpoint),
    "new_action": lambda target, endpoint: new_action(target, endpoint),
}
```

Add it to `DEFAULT_APPROVED_ACTIONS` **only** once you've completed the dry-run stage below —
until then, keep it out of the default list so `select_response_action()` can't pick it.

## 4. Dry-run before enabling

The Day 39 fix added a global kill switch, `RESPONSE_AUTO_EXECUTE` (defaults to `false`). Use it:

1. Deploy with the action wired into `ACTION_DISPATCH` but **not** in `DEFAULT_APPROVED_ACTIONS`,
   and `RESPONSE_AUTO_EXECUTE=false`.
2. Manually invoke the function directly (like `python3 -m tools.response_tools`'s existing
   `__main__` smoke tests) against a real test target, and verify:
   - the intended effect actually happened (e.g. `iptables -L` shows the rule)
   - the undo function cleanly reverses it
   - both calls are logged to `siem-response-log`, success and induced-failure cases alike
3. Add it to `DEFAULT_APPROVED_ACTIONS` but keep `RESPONSE_AUTO_EXECUTE=false` for at least a
   few production cycles — this lets `select_response_action()` pick it and log the *decision*
   without executing anything, so you can review whether it would have fired appropriately.
4. Only then set `RESPONSE_AUTO_EXECUTE=true` in that environment.

## 5. Confidence threshold

`RESPONSE_CONFIDENCE_THRESHOLD = 80` (in `response_agent.py`) gates all actions today — a
`suspicious` verdict below 80% confidence never triggers any action, regardless of what's in
`approved_actions`. If your new action is more (or less) risky than blocking an IP, consider a
per-action threshold rather than changing the global one:

```python
ACTION_THRESHOLDS = {
    "block_ip": 80,
    "isolate_endpoint": 80,
    "new_action": 90,   # e.g. something harder to reverse gets a higher bar
}
```

## 6. Testing

Follow the `test_day31.py` / `test_day33.py` pattern:
- 3 decision-logic cases: suspicious+high-confidence (action selected), suspicious+low-confidence
  (no action), benign+high-confidence (no action).
- Live test: fire the real action against a test target, manually verify the effect, then undo
  and verify cleanup — same as Day 32/33's `iptables -L` checks.
- ES verification: confirm the log entry exists in `siem-response-log`. **Add a short
  `time.sleep(1.5)` before checking** — Day 33 hit a false-negative test failure from checking
  before Elasticsearch's ~1s refresh interval caught up. This is a known gotcha, not a new one.

## 7. Checklist before merging a new response action

- [ ] Paired reversal function exists, or human-approval-only is explicitly enforced
- [ ] Every call (success and failure) logged to `siem-response-log`
- [ ] Response body checked for tool-specific failure indicators, not just HTTP status
- [ ] Dry-run stage completed: wired but not auto-executing, manually verified
- [ ] Added to `DEFAULT_APPROVED_ACTIONS` only after dry-run
- [ ] `RESPONSE_AUTO_EXECUTE` left `false` until confidence in false-positive rate is established
- [ ] Confidence threshold set appropriately for the action's risk/reversibility
- [ ] `time.sleep` buffer in any ES-write verification test
