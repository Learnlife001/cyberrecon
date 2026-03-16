import requests
import socket


def run(domain):
    """
    Return IP and geolocation info for the given domain as a dictionary.
    On failure, returns {"error": "..."}.
    """
    try:
        ip = socket.gethostbyname(domain)
        response = requests.get(f"https://ipinfo.io/{ip}/json")
        data = response.json()

        return {
            "ip": ip,
            "country": data.get("country"),
            "region": data.get("region"),
            "city": data.get("city"),
            "org": data.get("org"),
            "loc": data.get("loc"),
            "timezone": data.get("timezone"),
        }
    except Exception as e:
        return {"error": f"Failed to get IP info: {e}"}
