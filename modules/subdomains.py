import requests


def run(domain):
    """
    Return a list of discovered subdomains for the given domain.
    On error or no results, returns an empty list.
    """
    subdomains = []

    try:
        url = f"https://api.hackertarget.com/hostsearch/?q={domain}"
        response = requests.get(url)

        if "error" in response.text.lower() or response.status_code != 200:
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
