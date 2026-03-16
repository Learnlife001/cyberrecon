import dns.resolver


def run(domain):
    """
    Return DNS records for the given domain as a structured dictionary.
    Keys: A, AAAA, MX, NS, TXT.
    On overall failure, returns {"error": "..."}.
    """
    result = {
        "A": [],
        "AAAA": [],
        "MX": [],
        "NS": [],
        "TXT": [],
    }

    try:
        # A record
        try:
            a_records = dns.resolver.resolve(domain, "A")
            result["A"] = [str(rdata) for rdata in a_records]
        except Exception:
            # If A records cannot be resolved, leave list empty.
            pass

        # AAAA record
        try:
            aaaa_records = dns.resolver.resolve(domain, "AAAA")
            result["AAAA"] = [str(rdata) for rdata in aaaa_records]
        except Exception:
            pass

        # MX record
        try:
            mx_records = dns.resolver.resolve(domain, "MX")
            result["MX"] = [
                {
                    "exchange": str(rdata.exchange),
                    "priority": int(rdata.preference),
                }
                for rdata in mx_records
            ]
        except Exception:
            pass

        # NS record
        try:
            ns_records = dns.resolver.resolve(domain, "NS")
            result["NS"] = [str(rdata) for rdata in ns_records]
        except Exception:
            pass

        # TXT record
        try:
            txt_records = dns.resolver.resolve(domain, "TXT")
            result["TXT"] = [rdata.to_text() for rdata in txt_records]
        except Exception:
            pass

        return result

    except Exception as e:
        return {"error": f"DNS lookup failed: {e}"}
