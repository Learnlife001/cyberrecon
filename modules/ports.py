import nmap

def run(domain):
    print(f"\n[PORT SCANNER] Scanning common ports on {domain}...")

    scanner = nmap.PortScanner()

    try:
        # Scan top 1000 ports (default) for TCP only
        scanner.scan(domain, arguments="-T4")

        for host in scanner.all_hosts():
            print(f" Host: {host}")
            print(f" State: {scanner[host].state()}")
            
            for proto in scanner[host].all_protocols():
                print(f" Protocol: {proto}")
                ports = scanner[host][proto].keys()
                for port in sorted(ports):
                    state = scanner[host][proto][port]['state']
                    name = scanner[host][proto][port]['name']
                    print(f"  Port: {port} | State: {state} | Service: {name}")
    except Exception as e:
        print(f" [ERROR] Nmap scan failed: {e}")
