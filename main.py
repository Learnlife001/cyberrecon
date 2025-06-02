from modules import subdomains, ports, whois_lookup, tech_stack, dns_info, ip_info

def main():
    raw_input = input("Enter target domain (e.g. example.com): ").strip()
    target = raw_input.replace("https://", "").replace("http://", "").strip("/")

    print("\n[+] Getting DNS Info...")
    dns_info.run(target)

    print("\n[+] Getting IP Info...")
    ip_info.run(target)

    print("\n[+] Enumerating Subdomains...")
    subdomains.run(target)

    print("\n[+] Scanning Open Ports...")
    ports.run(target)

    print("\n[+] Running WHOIS Lookup...")
    whois_lookup.run(target)

    print("\n[+] Detecting Tech Stack...")
    tech_stack.run(target)

if __name__ == "__main__":
    main()
