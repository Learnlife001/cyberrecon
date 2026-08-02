import os
import requests


def run(domain):
    """
    Return a list of discovered subdomains for the given domain.
    On error or no results, returns an empty list.
    """
    subdomains = []

    try:
        api_url = os.getenv("SUBDOMAIN_API_URL") or f"https://api.hackertarget.com/hostsearch/?q={domain}"
        response = requests.get(api_url, timeout=10)
        response.raise_for_status()

        if "error" in response.text.lower():
            return subdomains

        results = response.text.strip().split("\n")
        for entry in results:
            if not entry:
                continue
            subdomain = entry.split(",")[0]
            if subdomain:
                subdomains.append(subdomain)

        return subdomains
    except Exception:
        return subdomains
