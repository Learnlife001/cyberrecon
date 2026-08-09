"""WHOIS intelligence with standards-based RDAP fallback."""

from __future__ import annotations

from typing import Any

import requests
import whois


EMPTY_RESULT = {
    "domain_name": None,
    "registrar": None,
    "creation_date": None,
    "expiration_date": None,
    "name_servers": None,
    "emails": None,
}


def _rdap_event(payload: dict[str, Any], action: str) -> str | None:
    for event in payload.get("events", []):
        if event.get("eventAction") == action:
            return event.get("eventDate")
    return None


def _rdap_registrar(payload: dict[str, Any]) -> str | None:
    for entity in payload.get("entities", []):
        if "registrar" not in entity.get("roles", []):
            continue
        card = entity.get("vcardArray", [])
        if len(card) != 2:
            continue
        for field in card[1]:
            if len(field) >= 4 and field[0] == "fn":
                return str(field[3])
    return None


def _rdap_lookup(domain: str) -> dict[str, Any]:
    response = requests.get(
        f"https://rdap.org/domain/{domain}",
        headers={"Accept": "application/rdap+json", "User-Agent": "CyberRecon/1.0"},
        timeout=10,
    )
    response.raise_for_status()
    payload = response.json()
    nameservers = [item.get("ldhName") for item in payload.get("nameservers", []) if item.get("ldhName")]
    return {
        "domain_name": payload.get("ldhName") or domain,
        "registrar": _rdap_registrar(payload),
        "creation_date": _rdap_event(payload, "registration"),
        "expiration_date": _rdap_event(payload, "expiration"),
        "name_servers": nameservers or None,
        "emails": None,
        "source": "rdap",
    }


def run(domain: str) -> dict[str, Any]:
    try:
        info = whois.whois(domain)
        result = {
            "domain_name": getattr(info, "domain_name", None),
            "registrar": getattr(info, "registrar", None),
            "creation_date": getattr(info, "creation_date", None),
            "expiration_date": getattr(info, "expiration_date", None),
            "name_servers": getattr(info, "name_servers", None),
            "emails": getattr(info, "emails", None),
            "source": "whois",
        }
        if any(result.get(key) for key in ("registrar", "creation_date", "expiration_date", "name_servers")):
            return result
    except Exception:
        pass

    try:
        return _rdap_lookup(domain)
    except (requests.RequestException, ValueError):
        return {**EMPTY_RESULT, "source": "unavailable"}
