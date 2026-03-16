import whois


def run(domain):
    """
    Return WHOIS information for the given domain as a dictionary.
    On failure, returns {"error": "..."}.
    """
    try:
        info = whois.whois(domain)

        return {
            "domain_name": getattr(info, "domain_name", None),
            "registrar": getattr(info, "registrar", None),
            "creation_date": getattr(info, "creation_date", None),
            "expiration_date": getattr(info, "expiration_date", None),
            "name_servers": getattr(info, "name_servers", None),
            "emails": getattr(info, "emails", None),
        }
    except Exception as e:
        return {"error": f"WHOIS lookup failed: {e}"}
