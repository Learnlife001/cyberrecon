import logging
import os
import shutil

import nmap

logger = logging.getLogger(__name__)


def run(domain):
    """
    Run an Nmap scan against the given domain.
    """

    results = []

    try:
        configured_path = os.getenv("NMAP_PATH")
        nmap_path = configured_path or shutil.which("nmap")
        if not nmap_path:
            logger.warning("Nmap is unavailable; skipping port scan")
            return results

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
        return []
