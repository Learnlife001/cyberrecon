"""Server-side transactional alert email delivery through Resend."""

from __future__ import annotations

import html
import os
from dataclasses import dataclass
from email.utils import parseaddr
from typing import Mapping

import requests


RESEND_EMAILS_URL = "https://api.resend.com/emails"
DEFAULT_FROM_EMAIL = "CyberRecon by CGregLab Security <alerts@cgreglab.space>"
DEFAULT_SUPPORT_EMAIL = "support@cgreglab.space"


class EmailConfigurationError(RuntimeError):
    """Raised when required server-side email configuration is missing."""


class EmailDeliveryError(RuntimeError):
    """Raised when the provider cannot accept an email for delivery."""


@dataclass(frozen=True)
class EmailDelivery:
    message_id: str
    recipient: str
    provider: str = "resend"


def _mailbox(value: str, setting_name: str) -> str:
    candidate = value.strip()
    address = parseaddr(candidate)[1]
    if "\r" in candidate or "\n" in candidate or "@" not in address:
        raise EmailConfigurationError(f"{setting_name} is not a valid email address")
    return candidate


def _safe_header(value: str, field_name: str) -> str:
    candidate = value.strip()
    if not candidate or "\r" in candidate or "\n" in candidate:
        raise EmailConfigurationError(f"{field_name} is not a valid email header")
    return candidate


def _safe_https_url(value: str | None) -> str | None:
    if value is None:
        return None
    candidate = value.strip()
    if not candidate.startswith("https://"):
        raise EmailConfigurationError("Alert action URLs must use HTTPS")
    return candidate


def render_alert_email(
    *,
    title: str,
    introduction: str,
    severity: str = "info",
    details: Mapping[str, object] | None = None,
    action_url: str | None = None,
    action_label: str = "Open CyberRecon",
) -> tuple[str, str]:
    """Return email-client-friendly HTML and a plain-text alternative."""

    severity_styles = {
        "operational": ("Operational", "#34d399", "#063b2e"),
        "info": ("Information", "#67e8f9", "#083344"),
        "warning": ("Warning", "#fbbf24", "#422006"),
        "critical": ("Critical", "#fb7185", "#4c0519"),
    }
    severity_key = severity.strip().lower()
    severity_label, accent, badge_background = severity_styles.get(
        severity_key, severity_styles["info"]
    )
    safe_title = html.escape(title.strip())
    safe_introduction = html.escape(introduction.strip())
    safe_action_url = _safe_https_url(action_url)
    safe_action_label = html.escape(action_label.strip())
    detail_items = [(str(label), str(value)) for label, value in (details or {}).items()]

    detail_rows = "".join(
        (
            '<tr><td style="padding:12px 0;border-bottom:1px solid #20283a;'
            'color:#8b97ad;font-size:12px;letter-spacing:.04em;text-transform:uppercase;'
            'vertical-align:top;width:38%;">'
            f"{html.escape(label)}</td>"
            '<td style="padding:12px 0;border-bottom:1px solid #20283a;'
            'color:#eef2ff;font-size:14px;line-height:1.5;vertical-align:top;">'
            f"{html.escape(value)}</td></tr>"
        )
        for label, value in detail_items
    )
    details_block = (
        '<table role="presentation" width="100%" cellspacing="0" cellpadding="0" '
        f'style="margin:24px 0 8px;border-collapse:collapse;">{detail_rows}</table>'
        if detail_rows
        else ""
    )
    action_block = (
        '<table role="presentation" cellspacing="0" cellpadding="0" style="margin-top:28px;">'
        '<tr><td style="border-radius:10px;background:#6d4aff;">'
        f'<a href="{html.escape(safe_action_url, quote=True)}" '
        'style="display:inline-block;padding:13px 20px;color:#ffffff;text-decoration:none;'
        'font-size:14px;font-weight:700;">'
        f"{safe_action_label}</a></td></tr></table>"
        if safe_action_url
        else ""
    )

    html_body = f"""<!doctype html>
<html lang="en">
  <head>
    <meta charset="utf-8">
    <meta name="viewport" content="width=device-width,initial-scale=1">
    <title>{safe_title}</title>
  </head>
  <body style="margin:0;padding:0;background:#050816;color:#eef2ff;font-family:Arial,Helvetica,sans-serif;">
    <div style="display:none;max-height:0;overflow:hidden;color:transparent;opacity:0;">
      {safe_title} — CyberRecon security notification.
    </div>
    <table role="presentation" width="100%" cellspacing="0" cellpadding="0" style="background:#050816;">
      <tr>
        <td align="center" style="padding:36px 16px;">
          <table role="presentation" width="100%" cellspacing="0" cellpadding="0"
                 style="max-width:620px;border:1px solid #252e44;border-radius:18px;background:#0b1020;overflow:hidden;">
            <tr>
              <td style="padding:24px 30px;border-bottom:1px solid #20283a;background:#080d1a;">
                <table role="presentation" width="100%" cellspacing="0" cellpadding="0">
                  <tr>
                    <td style="vertical-align:middle;">
                      <span style="display:inline-block;width:42px;height:42px;line-height:42px;text-align:center;
                                   border-radius:12px;background:#6d4aff;color:#ffffff;font-size:14px;font-weight:800;">CR</span>
                      <span style="display:inline-block;margin-left:12px;vertical-align:middle;">
                        <strong style="display:block;color:#ffffff;font-size:17px;">CyberRecon</strong>
                        <span style="display:block;margin-top:3px;color:#8b97ad;font-size:11px;letter-spacing:.08em;
                                     text-transform:uppercase;">by CGregLab Security</span>
                      </span>
                    </td>
                    <td align="right" style="vertical-align:middle;">
                      <span style="display:inline-block;padding:7px 10px;border:1px solid {accent};border-radius:999px;
                                   background:{badge_background};color:{accent};font-size:11px;font-weight:700;
                                   letter-spacing:.06em;text-transform:uppercase;">{severity_label}</span>
                    </td>
                  </tr>
                </table>
              </td>
            </tr>
            <tr>
              <td style="padding:34px 30px 30px;">
                <p style="margin:0 0 12px;color:#8b7cff;font-size:12px;font-weight:700;letter-spacing:.12em;
                          text-transform:uppercase;">Security notification</p>
                <h1 style="margin:0;color:#ffffff;font-size:28px;line-height:1.25;">{safe_title}</h1>
                <p style="margin:16px 0 0;color:#b9c2d6;font-size:15px;line-height:1.7;">{safe_introduction}</p>
                {details_block}
                {action_block}
              </td>
            </tr>
            <tr>
              <td style="padding:20px 30px;border-top:1px solid #20283a;background:#080d1a;color:#738097;
                         font-size:12px;line-height:1.6;">
                This operational message was sent by CyberRecon. Reply to this email to contact CGregLab Security support.
              </td>
            </tr>
          </table>
        </td>
      </tr>
    </table>
  </body>
</html>"""

    text_lines = [
        "CyberRecon by CGregLab Security",
        severity_label.upper(),
        "",
        title.strip(),
        introduction.strip(),
    ]
    if detail_items:
        text_lines.extend(["", "Details"])
        text_lines.extend(f"- {label}: {value}" for label, value in detail_items)
    if safe_action_url:
        text_lines.extend(["", f"{action_label.strip()}: {safe_action_url}"])
    text_lines.extend(["", "Support: support@cgreglab.space"])
    return html_body, "\n".join(text_lines)


def send_alert_email(
    *,
    recipient: str,
    subject: str,
    title: str,
    introduction: str,
    severity: str = "info",
    details: Mapping[str, object] | None = None,
    action_url: str | None = None,
    action_label: str = "Open CyberRecon",
    idempotency_key: str | None = None,
    api_key: str | None = None,
    sender: str | None = None,
    reply_to: str | None = None,
    timeout_seconds: float = 10.0,
) -> EmailDelivery:
    """Render and send one transactional alert through the Resend REST API."""

    resolved_api_key = (api_key or os.getenv("RESEND_API_KEY", "")).strip()
    if not resolved_api_key.startswith("re_"):
        raise EmailConfigurationError("RESEND_API_KEY is not configured")

    resolved_recipient = _mailbox(recipient, "ALERT_RECIPIENT_EMAIL")
    resolved_sender = _mailbox(
        sender or os.getenv("ALERT_FROM_EMAIL", DEFAULT_FROM_EMAIL), "ALERT_FROM_EMAIL"
    )
    resolved_reply_to = _mailbox(
        reply_to or os.getenv("SUPPORT_EMAIL", DEFAULT_SUPPORT_EMAIL), "SUPPORT_EMAIL"
    )
    resolved_subject = _safe_header(subject, "Email subject")
    html_body, text_body = render_alert_email(
        title=title,
        introduction=introduction,
        severity=severity,
        details=details,
        action_url=action_url,
        action_label=action_label,
    )

    headers = {
        "Authorization": f"Bearer {resolved_api_key}",
        "Content-Type": "application/json",
    }
    if idempotency_key:
        resolved_idempotency_key = _safe_header(idempotency_key, "Idempotency-Key")
        if len(resolved_idempotency_key) > 256:
            raise EmailConfigurationError("Idempotency-Key must be 256 characters or fewer")
        headers["Idempotency-Key"] = resolved_idempotency_key

    try:
        response = requests.post(
            RESEND_EMAILS_URL,
            headers=headers,
            json={
                "from": resolved_sender,
                "to": [parseaddr(resolved_recipient)[1]],
                "subject": resolved_subject,
                "html": html_body,
                "text": text_body,
                "reply_to": parseaddr(resolved_reply_to)[1],
                "tags": [{"name": "category", "value": "security-alert"}],
            },
            timeout=timeout_seconds,
        )
    except requests.RequestException as exc:
        raise EmailDeliveryError("Unable to reach the email provider") from exc

    if response.status_code not in {200, 201}:
        request_id = response.headers.get("x-request-id")
        suffix = f" (request {request_id})" if request_id else ""
        raise EmailDeliveryError(
            f"Email provider rejected the request with HTTP {response.status_code}{suffix}"
        )

    try:
        message_id = str(response.json()["id"])
    except (KeyError, TypeError, ValueError) as exc:
        raise EmailDeliveryError("Email provider returned an invalid response") from exc

    return EmailDelivery(message_id=message_id, recipient=parseaddr(resolved_recipient)[1])
