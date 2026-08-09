"""Explainable phishing-risk analysis with bounded, non-executing site inspection."""

from __future__ import annotations

import ipaddress
import os
import re
import socket
from datetime import datetime, timezone
from difflib import SequenceMatcher
from typing import Any
from urllib.parse import quote, urljoin, urlparse

import requests


BRANDS = {
    "amazon": ("Amazon", "amazon.com", ("amazon",)),
    "apple": ("Apple", "apple.com", ("apple",)),
    "binance": ("Binance", "binance.com", ("binance",)),
    "coinbase": ("Coinbase", "coinbase.com", ("coinbase",)),
    "dhl": ("DHL", "dhl.com", ("dhl",)),
    "discord": ("Discord", "discord.com", ("discord",)),
    "dropbox": ("Dropbox", "dropbox.com", ("dropbox",)),
    "facebook": ("Facebook", "facebook.com", ("facebook",)),
    "github": ("GitHub", "github.com", ("github",)),
    "google": ("Google", "google.com", ("google",)),
    "instagram": ("Instagram", "instagram.com", ("instagram",)),
    "linkedin": ("LinkedIn", "linkedin.com", ("linkedin",)),
    "microsoft": ("Microsoft", "microsoft.com", ("microsoft",)),
    "netflix": ("Netflix", "netflix.com", ("netflix",)),
    "office": ("Microsoft 365", "microsoft.com", ("microsoft 365", "office 365")),
    "outlook": ("Microsoft Outlook", "outlook.com", ("microsoft outlook", "outlook")),
    "paypal": ("PayPal", "paypal.com", ("paypal",)),
    "revolut": ("Revolut", "revolut.com", ("revolut",)),
    "spaceandtime": ("Space and Time", "spaceandtime.io", ("space and time", "space & time")),
    "stripe": ("Stripe", "stripe.com", ("stripe",)),
    "whatsapp": ("WhatsApp", "whatsapp.com", ("whatsapp",)),
}

SUSPICIOUS_TERMS = {
    "account", "auth", "confirm", "login", "password", "recover", "secure",
    "signin", "support", "unlock", "update", "verification", "verify", "wallet",
}
HIGH_RISK_PHRASES = {
    "connect wallet", "import wallet", "recovery phrase", "seed phrase",
    "secret phrase", "sign transaction", "validate wallet", "wallet verification",
}
MAX_HTML_BYTES = 512_000
MAX_SCRIPT_BYTES = 384_000
MAX_SCRIPTS = 3
USER_AGENT = "CyberRecon-Safety-Scanner/1.0 (+https://cgreglab.space)"


def _first(value: Any) -> Any:
    if isinstance(value, (list, tuple)):
        return value[0] if value else None
    return value


def _domain_age_days(creation_date: Any) -> int | None:
    raw = _first(creation_date)
    if raw is None:
        return None
    if isinstance(raw, datetime):
        created = raw
    else:
        try:
            created = datetime.fromisoformat(str(raw).replace("Z", "+00:00"))
        except ValueError:
            return None
    if created.tzinfo is None:
        created = created.replace(tzinfo=timezone.utc)
    return max(0, (datetime.now(timezone.utc) - created).days)


def _root_label(domain: str) -> str:
    labels = domain.lower().rstrip(".").split(".")
    return labels[-2] if len(labels) >= 2 else labels[0]


def _brand_match(domain: str) -> dict[str, Any] | None:
    root = _root_label(domain)
    compact = re.sub(r"[^a-z0-9]", "", root)
    candidates = [compact, *[part for part in re.split(r"[^a-z0-9]+", root) if part]]
    best: tuple[float, str, str, str] | None = None

    for token, (brand, canonical, _) in BRANDS.items():
        if domain == canonical or domain.endswith(f".{canonical}"):
            continue
        ratio = max(SequenceMatcher(None, candidate, token).ratio() for candidate in candidates)
        contains = any(
            (len(token) >= 3 and token in candidate)
            or (len(candidate) >= 4 and candidate in token)
            for candidate in candidates
        )
        if contains or ratio >= 0.72:
            candidate = (ratio + (0.25 if contains else 0), token, brand, canonical)
            if best is None or candidate[0] > best[0]:
                best = candidate

    if best is None:
        return None
    confidence, _, brand, canonical = best
    return {
        "brand": brand,
        "canonical_domain": canonical,
        "official_url": f"https://{canonical}",
        "similarity": round(min(confidence, 1.0), 2),
    }


def _public_hostname(hostname: str) -> bool:
    try:
        addresses = {item[4][0] for item in socket.getaddrinfo(hostname, 443, type=socket.SOCK_STREAM)}
    except socket.gaierror:
        return False
    return bool(addresses) and all(ipaddress.ip_address(address).is_global for address in addresses)


def _read_limited(response: requests.Response, limit: int) -> str:
    chunks: list[bytes] = []
    total = 0
    for chunk in response.iter_content(chunk_size=16_384):
        total += len(chunk)
        if total > limit:
            chunks.append(chunk[: max(0, limit - (total - len(chunk)))])
            break
        chunks.append(chunk)
    return b"".join(chunks).decode(response.encoding or "utf-8", errors="replace")


def _safe_fetch_details(url: str, limit: int) -> tuple[str, str, dict[str, str]]:
    current = url
    session = requests.Session()
    session.trust_env = False
    for _ in range(4):
        parsed = urlparse(current)
        if parsed.scheme != "https" or not parsed.hostname or not _public_hostname(parsed.hostname):
            raise ValueError("unsafe_target")
        response = session.get(
            current,
            allow_redirects=False,
            headers={"User-Agent": USER_AGENT, "Accept": "text/html,application/javascript;q=0.8"},
            stream=True,
            timeout=(3, 6),
        )
        if response.is_redirect:
            location = response.headers.get("location")
            response.close()
            if not location:
                raise ValueError("invalid_redirect")
            current = urljoin(current, location)
            continue
        response.raise_for_status()
        headers = {key.lower(): value for key, value in response.headers.items()}
        body = _read_limited(response, limit)
        response.close()
        return current, body, headers
    raise ValueError("too_many_redirects")


def _safe_fetch(url: str, limit: int) -> tuple[str, str]:
    final_url, body, _ = _safe_fetch_details(url, limit)
    return final_url, body


def _extract(pattern: str, text: str) -> str | None:
    match = re.search(pattern, text, flags=re.IGNORECASE | re.DOTALL)
    return re.sub(r"\s+", " ", match.group(1)).strip() if match else None


def _inspect_site(domain: str) -> dict[str, Any]:
    """Read bounded source text only; scripts are never executed."""
    try:
        final_url, html = _safe_fetch(f"https://{domain}", MAX_HTML_BYTES)
        title = _extract(r"<title[^>]*>(.*?)</title>", html)
        robots = _extract(r'<meta[^>]+name=["\']robots["\'][^>]+content=["\']([^"\']*)', html)
        if robots is None:
            robots = _extract(r'<meta[^>]+content=["\']([^"\']*)["\'][^>]+name=["\']robots["\']', html)
        canonical = _extract(r'<link[^>]+rel=["\']canonical["\'][^>]+href=["\']([^"\']*)', html)
        if canonical is None:
            canonical = _extract(r'<link[^>]+href=["\']([^"\']*)["\'][^>]+rel=["\']canonical["\']', html)

        script_text: list[str] = []
        base_host = urlparse(final_url).hostname
        sources = re.findall(r'<script[^>]+src=["\']([^"\']+)', html, flags=re.IGNORECASE)
        for source in sources[:MAX_SCRIPTS]:
            script_url = urljoin(final_url, source)
            script_host = urlparse(script_url).hostname
            if script_host != base_host:
                continue
            try:
                _, script = _safe_fetch(script_url, MAX_SCRIPT_BYTES)
                script_text.append(script)
            except (requests.RequestException, ValueError):
                continue

        searchable = re.sub(r"<[^>]+>", " ", html) + " " + " ".join(script_text)
        return {
            "source": "site_metadata",
            "status": "checked",
            "matched": False,
            "final_url": final_url,
            "title": title,
            "robots": robots,
            "canonical": canonical,
            "has_password_form": bool(re.search(r'<input[^>]+type=["\']password["\']', html, flags=re.IGNORECASE)),
            "searchable_text": searchable.lower()[:1_200_000],
        }
    except (requests.RequestException, ValueError) as exc:
        return {
            "source": "site_metadata",
            "status": "unavailable",
            "matched": False,
            "detail": type(exc).__name__,
            "searchable_text": "",
        }


def _google_web_risk(domain: str) -> dict[str, Any]:
    api_key = os.getenv("GOOGLE_WEB_RISK_API_KEY", "").strip()
    if not api_key:
        return {"source": "google_web_risk", "status": "not_configured", "matched": False}
    url = (
        "https://webrisk.googleapis.com/v1/uris:search"
        f"?uri={quote(f'https://{domain}', safe='')}&threatTypes=SOCIAL_ENGINEERING"
        f"&threatTypes=MALWARE&key={quote(api_key, safe='')}"
    )
    try:
        response = requests.get(url, timeout=5)
        response.raise_for_status()
        threat = response.json().get("threat", {})
        return {"source": "google_web_risk", "status": "checked", "matched": bool(threat), "threat_types": threat.get("threatTypes", [])}
    except (requests.RequestException, ValueError) as exc:
        return {"source": "google_web_risk", "status": "unavailable", "matched": False, "detail": type(exc).__name__}


def analyze(domain: str, whois_result: dict[str, Any] | None = None) -> dict[str, Any]:
    normalized = domain.lower().rstrip(".")
    whois_result = whois_result or {}
    score = 0
    signals: list[dict[str, Any]] = []

    def add_signal(code: str, label: str, severity: str, points: int) -> None:
        nonlocal score
        score += points
        signals.append({"code": code, "label": label, "severity": severity, "points": points})

    brand = _brand_match(normalized)
    if brand:
        add_signal("brand_lookalike", f"Domain resembles {brand['brand']} but is not its verified domain.", "high", 35)

    labels = set(re.split(r"[.-]", normalized))
    found_terms = sorted(labels.intersection(SUSPICIOUS_TERMS))
    if found_terms:
        add_signal("suspicious_keywords", f"Sensitive-account terms detected: {', '.join(found_terms)}.", "medium", min(15, 5 + len(found_terms) * 2))
    if "xn--" in normalized:
        add_signal("punycode", "Punycode may conceal lookalike characters.", "high", 20)
    if len(normalized.split(".")) >= 5:
        add_signal("deep_subdomain", "Unusually deep subdomain structure detected.", "low", 8)
    if len(normalized) >= 45:
        add_signal("long_domain", "The domain name is unusually long.", "low", 7)

    age_days = _domain_age_days(whois_result.get("creation_date"))
    if age_days is not None and age_days <= 30:
        add_signal("new_domain", f"Domain was registered only {age_days} days ago.", "high", 20)
    elif age_days is not None and age_days <= 180:
        add_signal("young_domain", f"Domain is approximately {age_days} days old.", "medium", 10)

    site = _inspect_site(normalized)
    searchable = site.get("searchable_text", "")
    claimed_brand: dict[str, Any] | None = None
    title_text = str(site.get("title") or "").lower()
    for _, (name, canonical, phrases) in BRANDS.items():
        if normalized == canonical or normalized.endswith(f".{canonical}"):
            continue
        content_match = any(phrase in searchable for phrase in phrases)
        title_match = any(phrase in title_text for phrase in phrases)
        same_brand = brand and canonical == brand["canonical_domain"]
        if title_match or (same_brand and content_match):
            claimed_brand = {"brand": name, "canonical_domain": canonical, "official_url": f"https://{canonical}"}
            break
    if claimed_brand and (not brand or claimed_brand["canonical_domain"] == brand["canonical_domain"]):
        brand = brand or claimed_brand
        add_signal("claimed_brand_identity", f"Website content presents itself as {brand['brand']} outside its verified domain.", "high", 20)

    robots = str(site.get("robots") or "").lower()
    if brand and ("noindex" in robots or "nofollow" in robots):
        add_signal("hidden_from_search", "The apparent brand site asks search engines not to index or follow it.", "medium", 10)

    canonical = site.get("canonical")
    if canonical and brand:
        canonical_host = urlparse(urljoin(site.get("final_url", f"https://{normalized}"), canonical)).hostname
        if canonical_host and canonical_host != normalized:
            add_signal("canonical_mismatch", f"Page canonical metadata points to {canonical_host}, not the scanned domain.", "high", 15)

    dangerous_phrases = sorted(phrase for phrase in HIGH_RISK_PHRASES if phrase in searchable)
    if dangerous_phrases:
        add_signal("wallet_or_secret_request", f"High-risk wallet language detected: {', '.join(dangerous_phrases[:3])}.", "high", 20)
    if site.get("has_password_form"):
        add_signal("password_form", "The page contains a password-entry form.", "medium", 10)

    web_risk = _google_web_risk(normalized)
    feeds = [web_risk, {key: value for key, value in site.items() if key not in {"searchable_text", "has_password_form"}}]
    matched_feeds = [feed for feed in feeds if feed.get("matched")]
    if matched_feeds:
        add_signal("known_threat", "A configured threat-intelligence provider lists this URL.", "critical", 70)

    score = min(score, 100)
    verdict = "known_phishing" if matched_feeds else "high_risk" if score >= 60 else "suspicious" if score >= 30 else "no_indicators"
    return {
        "verdict": verdict,
        "risk_score": score,
        "confidence": "high" if matched_feeds or score >= 60 else "medium" if signals else "low",
        "matched_brand": brand["brand"] if brand else None,
        "canonical_domain": brand["canonical_domain"] if brand else None,
        "official_url": brand["official_url"] if brand else None,
        "domain_age_days": age_days,
        "signals": signals,
        "threat_sources": feeds,
        "checked_at": datetime.now(timezone.utc).isoformat(),
        "method": "domain_rules_brand_identity_metadata_and_threat_intelligence",
        "disclaimer": "Automated evidence can produce false positives or miss threats. Verify high-risk findings independently.",
    }
