import os
import unittest
from datetime import datetime, timedelta, timezone
from unittest.mock import patch

from fastapi import HTTPException, Request
from fastapi.security import HTTPAuthorizationCredentials


os.environ.setdefault(
    "DATABASE_URL",
    "postgresql+psycopg://test:test@127.0.0.1:65432/cyberrecon_test",
)
os.environ.setdefault("SCAN_API_KEY", "unit-test-api-key")
os.environ.setdefault("SUPABASE_URL", "https://test-project.supabase.co")
os.environ.setdefault("TASK_QUEUE_MODE", "inprocess")

import api_server
import worker
from modules import (
    email_alerts,
    phishing,
    ports,
    scan_alerts,
    subdomains,
    tech_stack,
    whois_lookup,
)


class ApiSecurityTests(unittest.TestCase):
    def test_normalize_domain_removes_scheme_and_trailing_slash(self):
        self.assertEqual(api_server.normalize_domain(" HTTPS://Example.COM/ "), "example.com")

    @patch("api_server.socket.getaddrinfo")
    def test_public_domain_is_accepted(self, getaddrinfo):
        getaddrinfo.return_value = [(2, 1, 6, "", ("93.184.216.34", 0))]
        api_server.validate_public_domain("example.com")

    @patch("api_server.socket.getaddrinfo")
    def test_private_target_is_rejected(self, getaddrinfo):
        getaddrinfo.return_value = [(2, 1, 6, "", ("127.0.0.1", 0))]
        with self.assertRaises(HTTPException) as context:
            api_server.validate_public_domain("internal.example")
        self.assertEqual(context.exception.status_code, 400)

    @patch("modules.phishing.socket.getaddrinfo")
    def test_site_inspection_rejects_private_network_targets(self, getaddrinfo):
        getaddrinfo.return_value = [(2, 1, 6, "", ("127.0.0.1", 443))]
        with self.assertRaisesRegex(ValueError, "unsafe_target"):
            phishing._safe_fetch("https://internal.example", 1024)

    def test_api_key_uses_required_value(self):
        api_server.require_api_key("unit-test-api-key")
        with self.assertRaises(HTTPException) as context:
            api_server.require_api_key("wrong-key")
        self.assertEqual(context.exception.status_code, 401)

    def test_authentication_is_required_without_token_or_admin_key(self):
        with self.assertRaises(HTTPException) as context:
            api_server.require_principal(None, None)
        self.assertEqual(context.exception.status_code, 401)

    def test_invalid_bearer_token_is_rejected(self):
        credentials = HTTPAuthorizationCredentials(scheme="Bearer", credentials="invalid-token")
        with self.assertRaises(HTTPException) as context:
            api_server.require_principal(credentials, None)
        self.assertEqual(context.exception.status_code, 401)

    def test_admin_api_key_remains_available_for_automation(self):
        principal = api_server.require_principal(None, "unit-test-api-key")
        self.assertTrue(principal.is_admin)

    def test_non_admin_is_rejected_from_admin_endpoint(self):
        with self.assertRaises(HTTPException) as context:
            api_server.require_admin(api_server.Principal(user_id=None, email="user@example.com"))
        self.assertEqual(context.exception.status_code, 403)

    def test_api_key_principal_cannot_create_user_monitor(self):
        with self.assertRaises(HTTPException) as context:
            api_server.require_account(api_server.Principal(is_admin=True))
        self.assertEqual(context.exception.status_code, 403)

    def test_monitor_cadence_calculates_next_run(self):
        now = datetime(2026, 8, 20, 12, 0, tzinfo=timezone.utc)
        self.assertEqual(api_server.next_monitor_run("daily", now), now + timedelta(days=1))
        self.assertEqual(
            api_server.next_monitor_run("weekly", now), now + timedelta(days=7)
        )

    def test_high_risk_scan_builds_critical_phishing_warning(self):
        result = {
            "ports": [],
            "subdomains": [],
            "technologies": ["Cloudflare"],
            "phishing": {
                "verdict": "high_risk",
                "risk_score": 82,
                "official_url": "https://example.com",
            },
        }

        alert = scan_alerts.build_scan_alert(domain="example-login.test", result=result)

        self.assertEqual(alert.severity, "critical")
        self.assertIn("phishing warning", alert.subject.lower())
        self.assertEqual(alert.details["Likely official website"], "https://example.com")

    def test_posture_changes_take_priority_over_completion_notice(self):
        previous = {
            "ports": [{"port": 443, "protocol": "tcp", "service": "https"}],
            "subdomains": ["www.example.com"],
            "technologies": ["Cloudflare"],
            "dns": {"A": ["93.184.216.34"]},
            "ip_info": {"ip": "93.184.216.34"},
            "phishing": {"verdict": "no_indicators", "risk_score": 0},
        }
        current = {
            **previous,
            "ports": [
                {"port": 443, "protocol": "tcp", "service": "https"},
                {"port": 22, "protocol": "tcp", "service": "ssh"},
            ],
            "technologies": ["Cloudflare", "Next.js"],
        }

        alert = scan_alerts.build_scan_alert(
            domain="example.com",
            result=current,
            previous_result=previous,
        )

        self.assertEqual(alert.severity, "warning")
        self.assertIn("posture changed", alert.subject.lower())
        self.assertTrue(
            any("22/tcp" in str(value) for value in alert.details.values())
        )

    def test_unchanged_scheduled_scan_builds_report_notice(self):
        result = {
            "ports": [],
            "subdomains": [],
            "technologies": [],
            "phishing": {"verdict": "no_indicators", "risk_score": 0},
        }

        alert = scan_alerts.build_scan_alert(
            domain="example.com",
            result=result,
            previous_result=result,
            source="scheduled_weekly",
        )

        self.assertEqual(alert.severity, "operational")
        self.assertIn("scheduled cyberrecon report", alert.subject.lower())
        self.assertEqual(alert.details["Scan type"], "Scheduled weekly monitoring")

    @patch("api_server.send_alert_email")
    def test_completed_scan_dispatches_one_idempotent_alert(self, send_email):
        send_email.return_value = email_alerts.EmailDelivery(
            message_id="scan-alert-test",
            recipient="user@example.com",
        )

        api_server._deliver_scan_alert(
            job_id="11111111-1111-1111-1111-111111111111",
            domain="example.com",
            source="manual",
            recipient="user@example.com",
            result={
                "ports": [],
                "subdomains": [],
                "technologies": [],
                "phishing": {"verdict": "no_indicators", "risk_score": 0},
            },
            previous_result=None,
        )

        send_email.assert_called_once()
        self.assertEqual(
            send_email.call_args.kwargs["idempotency_key"],
            "cyberrecon-scan-11111111-1111-1111-1111-111111111111",
        )

    def test_monitoring_routes_are_exposed_in_openapi(self):
        paths = api_server.app.openapi()["paths"]
        self.assertIn("/monitors", paths)
        self.assertIn("/monitors/{monitor_id}", paths)
        self.assertIn("/admin/monitoring/run-due", paths)

    def test_alert_template_escapes_dynamic_content(self):
        html_body, text_body = email_alerts.render_alert_email(
            title="<script>alert(1)</script>",
            introduction="Unsafe <b>message</b>",
            details={"Target": "<example.test>"},
            action_url="https://cgreglab.space",
        )

        self.assertNotIn("<script>", html_body)
        self.assertIn("&lt;script&gt;", html_body)
        self.assertIn("Unsafe &lt;b&gt;message&lt;/b&gt;", html_body)
        self.assertIn("- Target: <example.test>", text_body)

    @patch("modules.email_alerts.requests.post")
    def test_alert_delivery_uses_resend_server_side(self, post):
        response = post.return_value
        response.status_code = 200
        response.headers = {}
        response.json.return_value = {"id": "email-test-id"}

        delivery = email_alerts.send_alert_email(
            recipient="support@cgreglab.space",
            subject="CyberRecon test",
            title="Delivery test",
            introduction="The alert channel is operational.",
            api_key="re_unit_test",
            sender="CyberRecon by CGregLab Security <alerts@cgreglab.space>",
            reply_to="support@cgreglab.space",
            idempotency_key="unit-test-delivery",
        )

        self.assertEqual(post.call_args.args[0], email_alerts.RESEND_EMAILS_URL)
        request_options = post.call_args.kwargs
        self.assertEqual(
            request_options["headers"]["Authorization"], "Bearer re_unit_test"
        )
        self.assertEqual(
            request_options["headers"]["Idempotency-Key"], "unit-test-delivery"
        )
        self.assertEqual(request_options["json"]["to"], ["support@cgreglab.space"])
        self.assertEqual(request_options["json"]["reply_to"], "support@cgreglab.space")
        self.assertEqual(delivery.message_id, "email-test-id")

    @patch.dict(os.environ, {"RESEND_API_KEY": ""}, clear=False)
    def test_alert_delivery_requires_server_key(self):
        with self.assertRaises(email_alerts.EmailConfigurationError):
            email_alerts.send_alert_email(
                recipient="support@cgreglab.space",
                subject="CyberRecon test",
                title="Delivery test",
                introduction="The alert channel is operational.",
            )

    @patch("api_server.send_alert_email")
    def test_admin_alert_route_uses_fixed_recipient(self, send_email):
        send_email.return_value = email_alerts.EmailDelivery(
            message_id="email-route-test",
            recipient="support@cgreglab.space",
        )
        request = Request(
            {
                "type": "http",
                "method": "POST",
                "path": "/admin/alerts/test",
                "headers": [],
                "client": ("203.0.113.72", 1234),
                "server": ("testserver", 80),
                "scheme": "http",
                "query_string": b"",
            }
        )

        response = api_server.send_test_alert(
            request,
            api_server.Principal(user_id=None, email="admin@example.com", is_admin=True),
        )

        self.assertEqual(response.status, "sent")
        self.assertEqual(response.message_id, "email-route-test")
        self.assertEqual(
            send_email.call_args.kwargs["recipient"], api_server.ALERT_RECIPIENT_EMAIL
        )
        self.assertTrue(
            send_email.call_args.kwargs["idempotency_key"].startswith(
                "cyberrecon-alert-test-"
            )
        )

    @patch("api_server.send_alert_email")
    def test_admin_alert_route_hides_provider_error(self, send_email):
        send_email.side_effect = email_alerts.EmailDeliveryError(
            "Provider response should remain private"
        )
        request = Request(
            {
                "type": "http",
                "method": "POST",
                "path": "/admin/alerts/test",
                "headers": [],
                "client": ("203.0.113.73", 1234),
                "server": ("testserver", 80),
                "scheme": "http",
                "query_string": b"",
            }
        )

        with self.assertRaises(HTTPException) as context:
            api_server.send_test_alert(
                request,
                api_server.Principal(
                    user_id=None, email="admin@example.com", is_admin=True
                ),
            )

        self.assertEqual(context.exception.status_code, 502)
        self.assertEqual(context.exception.detail, "Unable to send the test alert")

    @patch("modules.phishing._inspect_site")
    @patch("modules.phishing._google_web_risk")
    def test_phishing_analysis_flags_brand_lookalike(self, web_risk, inspect_site):
        inspect_site.return_value = {"source": "site_metadata", "status": "unavailable", "matched": False, "searchable_text": ""}
        web_risk.return_value = {
            "source": "google_web_risk",
            "status": "not_configured",
            "matched": False,
        }
        result = phishing.analyze("paypa1-secure-login.example")
        self.assertEqual(result["matched_brand"], "PayPal")
        self.assertEqual(result["official_url"], "https://paypal.com")
        self.assertIn(result["verdict"], {"suspicious", "high_risk"})

    @patch("modules.phishing._inspect_site")
    @patch("modules.phishing._google_web_risk")
    def test_phishing_analysis_does_not_flag_canonical_brand(self, web_risk, inspect_site):
        inspect_site.return_value = {"source": "site_metadata", "status": "checked", "matched": False, "title": "PayPal", "searchable_text": "paypal"}
        web_risk.return_value = {
            "source": "google_web_risk",
            "status": "not_configured",
            "matched": False,
        }
        result = phishing.analyze("paypal.com")
        self.assertEqual(result["verdict"], "no_indicators")
        self.assertIsNone(result["matched_brand"])

    @patch("modules.phishing._inspect_site")
    @patch("modules.phishing._google_web_risk")
    def test_phishing_analysis_flags_hidden_brand_impersonation(self, web_risk, inspect_site):
        web_risk.return_value = {"source": "google_web_risk", "status": "not_configured", "matched": False}
        inspect_site.return_value = {
            "source": "site_metadata",
            "status": "checked",
            "matched": False,
            "final_url": "https://spaceandtimeus.digital",
            "title": "Space & Time",
            "robots": "noindex, nofollow, noarchive",
            "canonical": None,
            "has_password_form": False,
            "searchable_text": "space & time",
        }
        result = phishing.analyze("spaceandtimeus.digital")
        self.assertEqual(result["verdict"], "high_risk")
        self.assertGreaterEqual(result["risk_score"], 60)
        self.assertEqual(result["matched_brand"], "Space and Time")
        self.assertEqual(result["official_url"], "https://spaceandtime.io")
        self.assertIn("hidden_from_search", {signal["code"] for signal in result["signals"]})

    @patch("modules.phishing._inspect_site")
    @patch("modules.phishing._google_web_risk")
    def test_strong_brand_lookalike_stays_high_risk_when_site_blocks_inspection(self, web_risk, inspect_site):
        web_risk.return_value = {"source": "google_web_risk", "status": "not_configured", "matched": False}
        inspect_site.return_value = {"source": "site_metadata", "status": "unavailable", "matched": False, "searchable_text": ""}
        result = phishing.analyze("spaceandtimeus.digital")
        self.assertEqual(result["verdict"], "high_risk")
        self.assertGreaterEqual(result["risk_score"], 60)
        self.assertIn("brand_on_risky_tld", {signal["code"] for signal in result["signals"]})

    @patch("modules.phishing._inspect_site")
    @patch("modules.phishing._google_web_risk")
    def test_short_domain_does_not_match_brand_by_single_letter(self, web_risk, inspect_site):
        web_risk.return_value = {"source": "google_web_risk", "status": "not_configured", "matched": False}
        inspect_site.return_value = {"source": "site_metadata", "status": "checked", "matched": False, "title": "X", "searchable_text": ""}
        result = phishing.analyze("x.com")
        self.assertIsNone(result["matched_brand"])
        self.assertEqual(result["verdict"], "no_indicators")

    def test_subdomain_validation_rejects_provider_error_text(self):
        self.assertIsNone(subdomains._valid("API count exceeded - Increase Quota with Membership", "x.com"))
        self.assertEqual(subdomains._valid("help.x.com", "x.com"), "help.x.com")

    @patch("modules.tech_stack._safe_fetch_details")
    def test_technology_fingerprints_source_without_executing_it(self, safe_fetch):
        safe_fetch.return_value = ("https://example.com", '<div id="__next_data__"></div><script src="cdn-cgi/app.js"></script>', {"server": "cloudflare"})
        self.assertEqual(tech_stack.run("example.com"), ["Cloudflare", "Next.js"])

    @patch("modules.whois_lookup.requests.get")
    @patch("modules.whois_lookup.whois.whois")
    def test_whois_uses_rdap_when_legacy_lookup_is_empty(self, legacy_whois, request_get):
        legacy_whois.return_value = type("WhoisResult", (), {})()
        response = request_get.return_value
        response.json.return_value = {
            "ldhName": "EXAMPLE.COM",
            "events": [{"eventAction": "registration", "eventDate": "1995-08-14T04:00:00Z"}],
            "entities": [{"roles": ["registrar"], "vcardArray": ["vcard", [["fn", {}, "text", "Example Registrar"]]]}],
        }
        result = whois_lookup.run("example.com")
        self.assertEqual(result["source"], "rdap")
        self.assertEqual(result["registrar"], "Example Registrar")

    @patch("modules.ports.socket.create_connection")
    def test_common_port_fallback_returns_only_open_services(self, create_connection):
        def connect(address, timeout):
            if address[1] == 443:
                return unittest.mock.MagicMock()
            raise OSError("closed")
        create_connection.side_effect = connect
        result = ports._common_port_fallback("example.com")
        self.assertEqual([(item["port"], item["service"]) for item in result], [(443, "https")])

    def test_worker_registers_durable_scan_task(self):
        self.assertEqual(worker.run_scan_job.name, "cyberrecon.run_scan")


if __name__ == "__main__":
    unittest.main()
