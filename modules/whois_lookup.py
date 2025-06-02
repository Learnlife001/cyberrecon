import whois

def run(domain):
    print(f"\n[WHOIS LOOKUP] Gathering WHOIS info for: {domain}")
    
    try:
        info = whois.whois(domain)
        
        print(f" Domain Name: {info.domain_name}")
        print(f" Registrar: {info.registrar}")
        print(f" Creation Date: {info.creation_date}")
        print(f" Expiration Date: {info.expiration_date}")
        print(f" Name Servers: {info.name_servers}")
        print(f" Emails: {info.emails}")
    except Exception as e:
        print(f" [ERROR] WHOIS lookup failed: {e}")
