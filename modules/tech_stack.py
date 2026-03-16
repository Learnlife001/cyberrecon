import requests

def run(domain):
    """
    Detect technologies using HTTP headers and simple fingerprinting.
    Returns a list of detected technologies.
    """

    technologies = []

    try:
        url = f"https://{domain}"
        response = requests.get(url, timeout=10)

        headers = response.headers

        server = headers.get("Server", "")
        powered = headers.get("X-Powered-By", "")

        if server:
            technologies.append(server)

        if powered:
            technologies.append(powered)

        header_str = str(headers).lower()

        if "cloudflare" in header_str:
            technologies.append("Cloudflare")

        if "nginx" in header_str:
            technologies.append("Nginx")

        if "apache" in header_str:
            technologies.append("Apache")

        if "php" in header_str:
            technologies.append("PHP")

        if "express" in header_str:
            technologies.append("Express")

    except Exception:
        return []

    return list(set(technologies))