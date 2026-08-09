import os
import unittest
from unittest.mock import patch

from fastapi import HTTPException
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
from modules import phishing, ports, subdomains, tech_stack, whois_lookup


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
