import requests

def run(domain):
    print(f"\n[SUBDOMAINS] Searching for subdomains of: {domain}")

    try:
        url = f"https://api.hackertarget.com/hostsearch/?q={domain}"
        response = requests.get(url)

        if "error" in response.text.lower() or response.status_code != 200:
            print("  [!] Error fetching subdomains or none found.")
            return

        results = response.text.strip().split("\n")
        if results:
            for entry in results:
                subdomain = entry.split(",")[0]
                print(f"  - {subdomain}")
        else:
            print("  [!] No subdomains found.")
    except Exception as e:
        print(f"  [ERROR] Failed to fetch subdomains: {e}")
