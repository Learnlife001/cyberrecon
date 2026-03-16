import nmap


def run(domain):
    """
    Run an Nmap scan against the given domain.
    """

    results = []

    try:
        scanner = nmap.PortScanner(
            nmap_search_path=("C:/Program Files (x86)/Nmap/nmap.exe",)
        )

        scanner.scan(domain, arguments="-T4")

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

    except Exception as e:
        print("Nmap scan error:", e)
        return []