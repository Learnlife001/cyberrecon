"""Non-executing technology fingerprinting from bounded website source."""

from __future__ import annotations

import re

from modules.phishing import _safe_fetch_details


FINGERPRINTS = {
    "Next.js": ("__next_data__", "/_next/static/"),
    "React": ("data-reactroot", "react-dom", "react.production.min"),
    "Vue.js": ("data-v-", "vue.runtime", "__vue__"),
    "Nuxt": ("__nuxt__", "/_nuxt/"),
    "Angular": ("ng-version", "<app-root"),
    "Svelte": ("svelte-", "__svelte"),
    "WordPress": ("wp-content/", "wp-includes/"),
    "Shopify": ("cdn.shopify.com", "shopify.theme"),
    "Webflow": ("data-wf-page", "webflow.js"),
    "Cloudflare": ("cdn-cgi/", "cloudflareinsights.com"),
    "Vite": ("/@vite/", "vite/modulepreload-polyfill"),
}


def run(domain: str) -> list[str]:
    try:
        _, html, headers = _safe_fetch_details(f"https://{domain}", 768_000)
    except Exception:
        return []

    source = html.lower()
    technologies = {name for name, markers in FINGERPRINTS.items() if any(marker in source for marker in markers)}
    server = headers.get("server", "").strip()
    powered_by = headers.get("x-powered-by", "").strip()
    if server:
        technologies.add("Cloudflare" if server.lower() == "cloudflare" else server)
    if powered_by:
        technologies.add(powered_by)
    if "cf-ray" in headers:
        technologies.add("Cloudflare")
    if "x-vercel-id" in headers:
        technologies.add("Vercel")
    if "x-render-origin-server" in headers:
        technologies.add("Render")
    generator = re.search(r'<meta[^>]+name=["\']generator["\'][^>]+content=["\']([^"\']+)', html, flags=re.IGNORECASE)
    if generator:
        technologies.add(generator.group(1).strip())
    return sorted(technologies)
