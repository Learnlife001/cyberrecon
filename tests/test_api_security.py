import os
import unittest
from unittest.mock import patch

from fastapi import HTTPException


os.environ.setdefault(
    "DATABASE_URL",
    "postgresql+psycopg://test:test@127.0.0.1:65432/cyberrecon_test",
)
os.environ.setdefault("SCAN_API_KEY", "unit-test-api-key")
os.environ.setdefault("TASK_QUEUE_MODE", "inprocess")

import api_server
import worker


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

    def test_api_key_uses_required_value(self):
        api_server.require_api_key("unit-test-api-key")
        with self.assertRaises(HTTPException) as context:
            api_server.require_api_key("wrong-key")
        self.assertEqual(context.exception.status_code, 401)

    def test_worker_registers_durable_scan_task(self):
        self.assertEqual(worker.run_scan_job.name, "cyberrecon.run_scan")


if __name__ == "__main__":
    unittest.main()
