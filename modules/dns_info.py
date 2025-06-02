import dns.resolver

def run(domain):
    try:
        print(f"\n[DNS INFO] Records for: {domain}")

        # A record
        try:
            a_records = dns.resolver.resolve(domain, 'A')
            print(" A Records:")
            for rdata in a_records:
                print(f"  - {rdata}")
        except:
            print("  No A records found.")

        # AAAA record
        try:
            aaaa_records = dns.resolver.resolve(domain, 'AAAA')
            print(" AAAA Records:")
            for rdata in aaaa_records:
                print(f"  - {rdata}")
        except:
            print("  No AAAA records found.")

        # MX record
        try:
            mx_records = dns.resolver.resolve(domain, 'MX')
            print(" MX Records:")
            for rdata in mx_records:
                print(f"  - {rdata.exchange} (Priority {rdata.preference})")
        except:
            print("  No MX records found.")

        # NS record
        try:
            ns_records = dns.resolver.resolve(domain, 'NS')
            print(" NS Records:")
            for rdata in ns_records:
                print(f"  - {rdata}")
        except:
            print("  No NS records found.")

        # TXT record
        try:
            txt_records = dns.resolver.resolve(domain, 'TXT')
            print(" TXT Records:")
            for rdata in txt_records:
                print(f"  - {rdata.to_text()}")
        except:
            print("  No TXT records found.")

    except Exception as e:
        print(f"[ERROR] DNS lookup failed: {e}")
