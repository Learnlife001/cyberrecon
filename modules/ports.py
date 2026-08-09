import logging
import os
import shutil
import socket

import nmap

logger = logging.getLogger(__name__)

COMMON_SERVICES = {
    21: "ftp", 22: "ssh", 25: "smtp", 53: "domain", 80: "http",
    110: "pop3", 143: "imap", 443: "https", 465: "smtps", 587: "submission",
    993: "imaps", 995: "pop3s", 3306: "mysql", 5432: "postgresql",
    6379: "redis", 8080: "http-proxy", 8443: "https-alt",
}


def _common_port_fallback(domain):
    results = []
    for port, service in COMMON_SERVICES.items():
        try:
            with socket.create_connection((domain, port), timeout=0.45):
                results.append({
                    "host": domain,
                    "host_state": "up",
                    "protocol": "tcp",
                    "port": port,
                    "state": "open",
                    "service": service,
                })
        except (OSError, TimeoutError):
            continue
    return results


def run(domain):
    """
    Run an Nmap scan against the given domain.
    """

    results = []

    try:
        configured_path = os.getenv("NMAP_PATH")
        nmap_path = configured_path or shutil.which("nmap")
        if not nmap_path:
            logger.warning("Nmap is unavailable; using bounded common-port scan")
            return _common_port_fallback(domain)

        scanner = nmap.PortScanner(nmap_search_path=(nmap_path,))
        scanner.scan(
            domain,
            arguments="-T4 -Pn -p 1-1024 --host-timeout 30s",
        )

        for host in scanner.all_hosts():
            host_state = scanner[host].state()

            for proto in scanner[host].all_protocols():
                ports = scanner[host][proto].keys()

                for port in sorted(ports):
                    port_data = scanner[host][proto][port]

                    results.append(
                        {
                            "host": host,
                            "host_state": host_state,
                            "protocol": proto,
                            "port": int(port),
                            "state": port_data.get("state"),
                            "service": port_data.get("name"),
                        }
                    )

        return results

    except Exception:
        logger.exception("Nmap scan failed for %s", domain)
        return _common_port_fallback(domain)
