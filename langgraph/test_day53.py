"""
test_day53.py — mocked test suite for tools/webhook_engine.py

Safe to run anywhere: requests.post and smtplib.SMTP are both mocked, and
the Elasticsearch logging call (_post) is mocked too, so no real network
or ES access is required. Mirrors the "mocked-ES test suite" convention
already used by test_day51.py.
"""

import sys
import types
import unittest
from unittest.mock import MagicMock, patch

# ---- stub out the elastic_tools._post dependency before import, same
#      trick used elsewhere in this project's mocked test suites.
#      `tools` itself stays a real, on-disk package (so `tools.webhook_engine`
#      still loads normally); only its `elastic_tools` submodule is faked,
#      since the real one isn't part of this deliverable. ----
import os
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

fake_elastic_tools = types.ModuleType("tools.elastic_tools")
fake_elastic_tools._post = MagicMock(return_value={"result": "created"})
sys.modules["tools.elastic_tools"] = fake_elastic_tools

from tools import webhook_engine as we  # noqa: E402


SAMPLE_ALERT = {
    "alert_es_id": "test-alert-001",
    "confidence_pct": 95,
    "technique": "T1110",
    "triage_result": {
        "verdict": "suspicious",
        "technique": "T1110",
        "summary": "Repeated SSH brute-force attempts detected from a known-bad IP.",
    },
    "alert": {"rule": {"description": "sshd: brute force"}, "data": {"srcip": "203.0.113.77"}},
}

SAMPLE_TENANT_CONFIG = {
    "tenant_id": "tenant_alpha",
    "notification_rules": [
        {"severity": "high", "channels": ["slack", "email"]},
        {"severity": "critical", "channels": ["slack", "teams", "email", "custom_webhook"]},
    ],
    "channel_config": {
        "slack": {"webhook_url": "https://hooks.slack.com/services/FAKE/FAKE/FAKE"},
        "teams": {"connector_url": "https://outlook.office.com/webhook/FAKE"},
        "email": {"to": ["soc@tenant-alpha.example.com"]},
        "custom_webhook": {"url": "https://example.com/hook", "headers": {"X-Api-Key": "fake"}},
    },
}


class TestSeverityResolution(unittest.TestCase):
    def test_critical(self):
        self.assertEqual(we.resolve_severity({"confidence_pct": 95}), "critical")

    def test_high(self):
        self.assertEqual(we.resolve_severity({"confidence_pct": 75}), "high")

    def test_medium(self):
        self.assertEqual(we.resolve_severity({"confidence_pct": 50}), "medium")

    def test_low(self):
        self.assertEqual(we.resolve_severity({"confidence_pct": 10}), "low")

    def test_missing_confidence_defaults_low(self):
        self.assertEqual(we.resolve_severity({}), "low")

    def test_bad_type_does_not_raise(self):
        self.assertEqual(we.resolve_severity({"confidence_pct": "not-a-number"}), "low")

    def test_chain_result_risk_score_fallback(self):
        alert = {"chain_result": {"risk_score": 92}}
        self.assertEqual(we.resolve_severity(alert), "critical")


class TestRuleMatching(unittest.TestCase):
    def test_high_severity_matches_high_rule_only(self):
        rules = SAMPLE_TENANT_CONFIG["notification_rules"]
        channels = we._matching_channels("high", rules)
        self.assertIn("slack", channels)
        self.assertIn("email", channels)
        self.assertNotIn("teams", channels)  # only under the critical rule

    def test_critical_severity_matches_both_rules_floor_semantics(self):
        rules = SAMPLE_TENANT_CONFIG["notification_rules"]
        channels = we._matching_channels("critical", rules)
        for ch in ("slack", "teams", "email", "custom_webhook"):
            self.assertIn(ch, channels)

    def test_low_severity_matches_nothing(self):
        rules = SAMPLE_TENANT_CONFIG["notification_rules"]
        channels = we._matching_channels("low", rules)
        self.assertEqual(channels, [])

    def test_exact_match_rule(self):
        rules = [{"severity": "high", "channels": ["slack"], "exact_match": True}]
        self.assertEqual(we._matching_channels("critical", rules), [])
        self.assertEqual(we._matching_channels("high", rules), ["slack"])

    def test_no_rules_configured(self):
        self.assertEqual(we._matching_channels("critical", []), [])


class TestFormatters(unittest.TestCase):
    def test_slack_message_has_required_blocks(self):
        msg = we.format_slack_message(SAMPLE_ALERT, "critical")
        self.assertIn("blocks", msg)
        header = msg["blocks"][0]
        self.assertEqual(header["type"], "header")
        self.assertIn("CRITICAL", header["text"]["text"])
        self.assertIn("T1110", json_dump_contains(msg, "T1110"))

    def test_teams_card_has_actionable_buttons(self):
        card = we.format_teams_card(SAMPLE_ALERT, "high")
        actions = card["attachments"][0]["content"]["actions"]
        titles = [a["title"] for a in actions]
        self.assertIn("Acknowledge", titles)
        self.assertIn("Escalate", titles)
        self.assertIn("View in Dashboard", titles)

    def test_email_html_contains_summary_table(self):
        html = we.format_email_html(SAMPLE_ALERT, "high")
        self.assertIn("<table", html)
        self.assertIn("T1110", html)
        self.assertIn("203.0.113.77", html)

    def test_email_html_includes_blast_radius_when_present(self):
        alert = dict(SAMPLE_ALERT, chain_result={"risk_score": 90, "blast_radius": 4})
        html = we.format_email_html(alert, "critical")
        self.assertIn("Blast radius", html)


def json_dump_contains(obj, needle):
    import json as _json
    s = _json.dumps(obj)
    return s if needle in s else ""


class TestSendNotifications(unittest.TestCase):
    @patch("tools.webhook_engine.requests.post")
    @patch("tools.webhook_engine.smtplib.SMTP")
    def test_high_severity_fires_slack_and_email_only(self, mock_smtp, mock_post):
        mock_post.return_value = MagicMock(status_code=200, text="ok")
        mock_smtp.return_value.__enter__.return_value = MagicMock()

        alert = dict(SAMPLE_ALERT, confidence_pct=75)  # -> high
        result = we.send_notifications(alert, SAMPLE_TENANT_CONFIG)

        self.assertEqual(result["severity"], "high")
        self.assertIn("slack", result["results"])
        self.assertIn("email", result["results"])
        self.assertNotIn("teams", result["results"])
        self.assertTrue(result["results"]["slack"]["success"])
        self.assertTrue(result["results"]["email"]["success"])

    @patch("tools.webhook_engine.requests.post")
    @patch("tools.webhook_engine.smtplib.SMTP")
    def test_critical_severity_fires_all_four_channels(self, mock_smtp, mock_post):
        mock_post.return_value = MagicMock(status_code=200, text="ok")
        mock_smtp.return_value.__enter__.return_value = MagicMock()

        result = we.send_notifications(SAMPLE_ALERT, SAMPLE_TENANT_CONFIG)  # confidence_pct=95 -> critical

        self.assertEqual(result["severity"], "critical")
        for ch in ("slack", "teams", "email", "custom_webhook"):
            self.assertIn(ch, result["results"])
            self.assertTrue(result["results"][ch]["success"], f"{ch} should have succeeded")

    @patch("tools.webhook_engine.requests.post")
    def test_one_channel_failing_does_not_block_others(self, mock_post):
        # Slack fails (500), everything else should still be attempted.
        def side_effect(url, *args, **kwargs):
            if "slack" in url or "hooks.slack" in url:
                return MagicMock(status_code=500, text="error")
            return MagicMock(status_code=200, text="ok")

        mock_post.side_effect = side_effect
        with patch("tools.webhook_engine.smtplib.SMTP") as mock_smtp:
            mock_smtp.return_value.__enter__.return_value = MagicMock()
            result = we.send_notifications(SAMPLE_ALERT, SAMPLE_TENANT_CONFIG)

        self.assertFalse(result["results"]["slack"]["success"])
        self.assertTrue(result["results"]["teams"]["success"])
        self.assertTrue(result["results"]["custom_webhook"]["success"])

    def test_low_severity_no_channels_attempted_no_crash(self):
        alert = dict(SAMPLE_ALERT, confidence_pct=5)
        result = we.send_notifications(alert, SAMPLE_TENANT_CONFIG)
        self.assertEqual(result["channels_attempted"], [])
        self.assertEqual(result["results"], {})

    def test_missing_channel_config_reports_failure_not_crash(self):
        tenant_config = {
            "tenant_id": "tenant_beta",
            "notification_rules": [{"severity": "critical", "channels": ["slack"]}],
            "channel_config": {},  # no slack webhook_url configured
        }
        result = we.send_notifications(SAMPLE_ALERT, tenant_config)
        self.assertFalse(result["results"]["slack"]["success"])
        self.assertIn("webhook_url", result["results"]["slack"]["error"])

    @patch("tools.webhook_engine.requests.post", side_effect=Exception("network unreachable"))
    def test_network_exception_never_raises_out_of_send_notifications(self, _mock_post):
        tenant_config = {
            "tenant_id": "tenant_alpha",
            "notification_rules": [{"severity": "critical", "channels": ["custom_webhook"]}],
            "channel_config": {"custom_webhook": {"url": "https://example.com/hook"}},
        }
        # Should not raise.
        result = we.send_notifications(SAMPLE_ALERT, tenant_config)
        self.assertFalse(result["results"]["custom_webhook"]["success"])


class TestNotificationLogging(unittest.TestCase):
    @patch("tools.webhook_engine.requests.post")
    @patch("tools.webhook_engine.smtplib.SMTP")
    def test_every_attempt_logged_including_failures(self, mock_smtp, mock_post):
        mock_post.return_value = MagicMock(status_code=200, text="ok")
        mock_smtp.return_value.__enter__.return_value = MagicMock()
        fake_elastic_tools._post.reset_mock()

        we.send_notifications(SAMPLE_ALERT, SAMPLE_TENANT_CONFIG)  # critical -> 4 channels

        self.assertEqual(fake_elastic_tools._post.call_count, 4)
        for call in fake_elastic_tools._post.call_args_list:
            index_path, doc = call.args
            self.assertEqual(index_path, f"{we.NOTIFICATION_LOG_INDEX}/_doc")
            self.assertIn("channel", doc)
            self.assertIn("success", doc)
            self.assertIn("tenant_id", doc)


if __name__ == "__main__":
    unittest.main(verbosity=2)
