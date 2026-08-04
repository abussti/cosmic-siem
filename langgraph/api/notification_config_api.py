"""
api/notification_config_api.py  —  Day 53

Small Flask blueprint exposing:

    GET  /api/v1/config/notifications?tenant_id=tenant_alpha
        -> current notification_rules + channel_config for that tenant

    POST /api/v1/config/notifications
        body: {"tenant_id": "tenant_alpha",
               "notification_rules": [...],
               "channel_config": {...}}
        -> validates shape, merges into the tenant's tenant_config doc via
           multi_tenant.tenant_manager, returns the updated document

This project has no existing REST API surface (everything else is a
pipeline/agent/CLI tool), so this is a new, minimal, single-purpose app
rather than an addition to a larger framework. It deliberately reuses
Day 51's tenant_manager as the only write path to tenant_config — no
direct Elasticsearch calls happen here, so tenant isolation guarantees
stay in exactly one place.
"""

from __future__ import annotations

from typing import Any, Dict

from flask import Flask, jsonify, request

from multi_tenant import tenant_manager as tm

app = Flask(__name__)

VALID_SEVERITIES = {"low", "medium", "high", "critical"}
VALID_CHANNELS = {"slack", "teams", "email", "custom_webhook", "pagerduty_webhook"}


def _validate_rules(rules: Any) -> str | None:
    if not isinstance(rules, list):
        return "notification_rules must be a list"
    for i, rule in enumerate(rules):
        if not isinstance(rule, dict):
            return f"rule[{i}] must be an object"
        if rule.get("severity") not in VALID_SEVERITIES:
            return f"rule[{i}].severity must be one of {sorted(VALID_SEVERITIES)}"
        channels = rule.get("channels")
        if not isinstance(channels, list) or not channels:
            return f"rule[{i}].channels must be a non-empty list"
        bad = [c for c in channels if c not in VALID_CHANNELS]
        if bad:
            return f"rule[{i}].channels has unknown channel type(s): {bad}"
    return None


@app.get("/api/v1/config/notifications")
def get_notifications():
    tenant_id = request.args.get("tenant_id")
    if not tenant_id:
        return jsonify({"success": False, "error": "tenant_id query param required"}), 400

    try:
        config = tm.get_tenant_config(tenant_id)
    except tm.TenantIsolationError as exc:
        return jsonify({"success": False, "error": str(exc)}), 400
    except Exception as exc:
        return jsonify({"success": False, "error": f"lookup failed: {exc}"}), 500

    if config is None:
        return jsonify({"success": False, "error": f"unknown tenant_id '{tenant_id}'"}), 404

    return jsonify(
        {
            "success": True,
            "tenant_id": tenant_id,
            "notification_rules": config.get("notification_rules", []),
            "channel_config": _redact_secrets(config.get("channel_config", {})),
        }
    )


@app.post("/api/v1/config/notifications")
def set_notifications():
    body: Dict[str, Any] = request.get_json(silent=True) or {}
    tenant_id = body.get("tenant_id")
    if not tenant_id:
        return jsonify({"success": False, "error": "tenant_id is required in the request body"}), 400

    rules = body.get("notification_rules", [])
    error = _validate_rules(rules)
    if error:
        return jsonify({"success": False, "error": error}), 400

    channel_config = body.get("channel_config", {})
    if not isinstance(channel_config, dict):
        return jsonify({"success": False, "error": "channel_config must be an object"}), 400

    try:
        existing = tm.get_tenant_config(tenant_id)
        if existing is None:
            return jsonify({"success": False, "error": f"unknown tenant_id '{tenant_id}'"}), 404

        updated = dict(existing)
        updated["notification_rules"] = rules
        updated["channel_config"] = channel_config

        result = tm.write_tenant_doc(tenant_id, "config", updated) if hasattr(
            tm, "write_tenant_doc"
        ) else None
        # tenant_config itself isn't a per-family index (alerts/hunts/responses) —
        # write it back the same way create_tenant() originally wrote it.
        tm._put(f"tenant_config/_doc/{tenant_id}", updated)  # noqa: SLF001 — same module, intentional
    except tm.TenantIsolationError as exc:
        return jsonify({"success": False, "error": str(exc)}), 400
    except Exception as exc:
        return jsonify({"success": False, "error": f"write failed: {exc}"}), 500

    return jsonify(
        {
            "success": True,
            "tenant_id": tenant_id,
            "notification_rules": rules,
            "channel_config": _redact_secrets(channel_config),
        }
    )


def _redact_secrets(channel_config: Dict[str, Any]) -> Dict[str, Any]:
    """Never echo webhook URLs / SMTP creds / routing keys back verbatim on GET."""
    redacted = {}
    secret_fields = {"webhook_url", "connector_url", "url", "routing_key", "password"}
    for channel, cfg in (channel_config or {}).items():
        if not isinstance(cfg, dict):
            redacted[channel] = cfg
            continue
        redacted[channel] = {
            k: ("***configured***" if k in secret_fields and v else v) for k, v in cfg.items()
        }
    return redacted


if __name__ == "__main__":
    app.run(port=5055, debug=False)
