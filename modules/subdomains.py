"""Passive subdomain discovery with validated provider fallbacks."""

from __future__ import annotations

import os
import re

import requests


DOMAIN_PATTERN = re.compile(r"^(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)+[a-z]{2,63}$")
PROVIDER_ERRORS = ("api count exceeded", "increase quota", "membership", "error", "invalid query")


def _valid(candidate: str, domain: str) -> str | None:
    value = candidate.lower().strip().lstrip("*.").rstrip(".")
    if value != domain and value.endswith(f".{domain}") and DOMAIN_PATTERN.fullmatch(value):
        return value
    return None


def _hackertarget(domain: str) -> list[str]:
    url = os.getenv("SUBDOMAIN_API_URL") or f"https://api.hackertarget.com/hostsearch/?q={domain}"
    response = requests.get(url, timeout=10)
    response.raise_for_status()
    body = response.text.strip()
    if any(message in body.lower() for message in PROVIDER_ERRORS):
        return []
    return [valid for line in body.splitlines() if (valid := _valid(line.split(",", 1)[0], domain))]


def _certificate_transparency(domain: str) -> list[str]:
    response = requests.get(
        "https://crt.sh/",
        params={"q": f"%.{domain}", "output": "json"},
        headers={"User-Agent": "CyberRecon/1.0"},
        timeout=15,
    )
    response.raise_for_status()
    discovered: set[str] = set()
    for record in response.json():
        for name in str(record.get("name_value", "")).splitlines():
            valid = _valid(name, domain)
            if valid:
                discovered.add(valid)
    return sorted(discovered)[:250]


def run(domain: str) -> list[str]:
    try:
        primary = sorted(set(_hackertarget(domain)))
        if primary:
            return primary[:250]
    except (requests.RequestException, ValueError):
        pass
    try:
        return _certificate_transparency(domain)
    except (requests.RequestException, ValueError):
        return []
