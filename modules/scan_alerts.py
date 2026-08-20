"""Classify completed scans and build concise customer alert content."""

from __future__ import annotations

from dataclasses import dataclass
from typing import Any, Mapping


HIGH_RISK_VERDICTS = {"known_phishing", "high_risk"}


@dataclass(frozen=True)
class ScanAlertContent:
    subject: str
    title: str
    introduction: str
    severity: str
    details: Mapping[str, object]
    action_label: str = "Review scan results"


def _string_set(value: object) -> set[str]:
    if not isinstance(value, list):
        return set()
    return {str(item).strip() for item in value if str(item).strip()}


def _port_set(result: Mapping[str, Any]) -> set[str]:
    ports: set[str] = set()
    for item in result.get("ports") or []:
        if not isinstance(item, Mapping):
            continue
        port = item.get("port")
        if port is None:
            continue
        protocol = str(item.get("protocol") or "tcp")
        service = str(item.get("service") or "unknown")
        ports.add(f"{port}/{protocol} ({service})")
    return ports


def _dns_addresses(result: Mapping[str, Any]) -> set[str]:
    dns = result.get("dns")
    if not isinstance(dns, Mapping):
        return set()
    return _string_set(list(dns.get("A") or []) + list(dns.get("AAAA") or []))


def _describe_set_change(label: str, before: set[str], after: set[str]) -> str | None:
    added = sorted(after - before)
    removed = sorted(before - after)
    if not added and not removed:
        return None

    fragments: list[str] = []
    if added:
        suffix = "" if len(added) <= 3 else f" and {len(added) - 3} more"
        fragments.append(f"added {', '.join(added[:3])}{suffix}")
    if removed:
        suffix = "" if len(removed) <= 3 else f" and {len(removed) - 3} more"
        fragments.append(f"removed {', '.join(removed[:3])}{suffix}")
    return f"{label}: {'; '.join(fragments)}"


def detect_security_changes(
    previous: Mapping[str, Any] | None,
    current: Mapping[str, Any],
) -> list[str]:
    """Return material posture changes between two normalized scan results."""

    if not previous:
        return []

    changes: list[str] = []
    comparisons = (
        ("Open services", _port_set(previous), _port_set(current)),
        (
            "Subdomains",
            _string_set(previous.get("subdomains")),
            _string_set(current.get("subdomains")),
        ),
        (
            "Technologies",
            _string_set(previous.get("technologies")),
            _string_set(current.get("technologies")),
        ),
        ("DNS addresses", _dns_addresses(previous), _dns_addresses(current)),
    )
    for label, before, after in comparisons:
        description = _describe_set_change(label, before, after)
        if description:
            changes.append(description)

    previous_ip = (previous.get("ip_info") or {}).get("ip")
    current_ip = (current.get("ip_info") or {}).get("ip")
    if previous_ip and current_ip and previous_ip != current_ip:
        changes.append(f"Primary IP changed from {previous_ip} to {current_ip}")

    previous_phishing = previous.get("phishing") or {}
    current_phishing = current.get("phishing") or {}
    previous_verdict = str(previous_phishing.get("verdict") or "unknown")
    current_verdict = str(current_phishing.get("verdict") or "unknown")
    previous_score = int(previous_phishing.get("risk_score") or 0)
    current_score = int(current_phishing.get("risk_score") or 0)
    if previous_verdict != current_verdict:
        changes.append(
            f"Phishing verdict changed from {previous_verdict} to {current_verdict}"
        )
    elif abs(current_score - previous_score) >= 10:
        changes.append(
            f"Phishing risk score changed from {previous_score} to {current_score}"
        )

    return changes


def _count(value: object) -> int:
    return len(value) if isinstance(value, list) else 0


def _source_label(source: str) -> str:
    if source == "scheduled_daily":
        return "Scheduled daily monitoring"
    if source == "scheduled_weekly":
        return "Scheduled weekly monitoring"
    return "Manual scan"


def build_scan_alert(
    *,
    domain: str,
    result: Mapping[str, Any],
    previous_result: Mapping[str, Any] | None = None,
    source: str = "manual",
) -> ScanAlertContent:
    """Prioritize phishing, change, scheduled, and completion notifications."""

    phishing = result.get("phishing") or {}
    verdict = str(phishing.get("verdict") or "unknown")
    risk_score = int(phishing.get("risk_score") or 0)
    official_url = phishing.get("official_url")
    changes = detect_security_changes(previous_result, result)

    details: dict[str, object] = {
        "Domain": domain,
        "Scan type": _source_label(source),
        "Phishing verdict": verdict.replace("_", " ").title(),
        "Risk score": f"{risk_score}/100",
        "Open services": _count(result.get("ports")),
        "Discovered subdomains": _count(result.get("subdomains")),
        "Detected technologies": _count(result.get("technologies")),
    }

    if verdict in HIGH_RISK_VERDICTS:
        if official_url:
            details["Likely official website"] = official_url
        details["Safety guidance"] = (
            "Do not enter passwords, wallet phrases, payment details, or personal data."
        )
        return ScanAlertContent(
            subject=f"High-risk phishing warning: {domain}",
            title="Potential phishing website detected",
            introduction=(
                f"CyberRecon found strong phishing or impersonation indicators on {domain}. "
                "Avoid proceeding until the evidence has been reviewed independently."
            ),
            severity="critical",
            details=details,
            action_label="Review phishing evidence",
        )

    if changes:
        for index, change in enumerate(changes[:5], start=1):
            details[f"Change {index}"] = change
        if len(changes) > 5:
            details["Additional changes"] = len(changes) - 5
        return ScanAlertContent(
            subject=f"Security posture changed: {domain}",
            title="Monitoring changes detected",
            introduction=(
                f"CyberRecon detected material differences between the latest scan of "
                f"{domain} and its previous result."
            ),
            severity="warning",
            details=details,
        )

    if source.startswith("scheduled_"):
        return ScanAlertContent(
            subject=f"Scheduled CyberRecon report: {domain}",
            title="Scheduled security report is ready",
            introduction=(
                f"The scheduled monitoring scan for {domain} completed successfully. "
                "No material changes or high-risk phishing indicators were detected."
            ),
            severity="operational",
            details=details,
        )

    return ScanAlertContent(
        subject=f"CyberRecon scan completed: {domain}",
        title="Security scan completed",
        introduction=(
            f"CyberRecon completed the requested assessment of {domain}. "
            "The latest reconnaissance results are ready for review."
        ),
        severity="operational",
        details=details,
    )
