from modules import subdomains, ports, whois_lookup, tech_stack, dns_info, ip_info


def run_recon(domain: str):
    """
    Central recon engine
    """

    target = domain.replace("https://", "").replace("http://", "").strip("/")

    print("Running DNS lookup...")
    dns_result = dns_info.run(target)

    print("Running IP lookup...")
    ip_result = ip_info.run(target)

    print("Running subdomain scan...")
    subdomains_result = subdomains.run(target)

    print("Running port scan...")
    ports_result = ports.run(target)

    print("Running WHOIS lookup...")
    whois_result = whois_lookup.run(target)

    print("Running tech stack detection...")
    tech_result = tech_stack.run(target)

    print("Recon completed")

    return {
        "domain": target,
        "dns": dns_result,
        "ip_info": ip_result,
        "subdomains": subdomains_result,
        "ports": ports_result,
        "whois": whois_result,
        "technologies": tech_result,
    }


def main():
    raw_input = input("Enter target domain (e.g. example.com): ").strip()
    result = run_recon(raw_input)
    print(result)


if __name__ == "__main__":
    main()