"""Formatters for AnalysisResult (Telegram HTML and plain text)."""

from __future__ import annotations

import html

from .analyzer import AnalysisResult, RiskLevel

_RISK_BADGE = {
    RiskLevel.HIGH: "🚨 HIGH RISK",
    RiskLevel.MEDIUM: "⚠️ MEDIUM RISK",
    RiskLevel.LOW: "🟢 LOW RISK",
}

_SEVERITY_ICON = {
    3: "🔴",
    2: "🟠",
    1: "🟡",
}


def format_telegram_html(result: AnalysisResult) -> str:
    """Format an AnalysisResult as safe Telegram HTML."""
    badge = _RISK_BADGE[result.risk_level]
    lines: list[str] = [
        f"<b>{html.escape(badge)}</b> (Score: {result.score}/10)",
        html.escape(result.summary),
        "",
    ]

    if result.warning_signs:
        lines.append("<b>🔎 Warning Signs Found</b>")
        for idx, sign in enumerate(result.warning_signs, start=1):
            icon = _SEVERITY_ICON.get(sign.severity, "🟡")
            lines.append(f"{idx}. {icon} <b>{html.escape(sign.title)}</b>")
            lines.append(f"   {html.escape(sign.explanation)}")
            if sign.evidence:
                evidence_str = ", ".join(f"<code>{html.escape(e)}</code>" for e in sign.evidence)
                lines.append(f"   <i>Matched:</i> {evidence_str}")
        lines.append("")
    else:
        lines.append("<b>🔎 Warning Signs Found</b>")
        lines.append("• No common fake-support red flags were matched.")
        lines.append("")

    if result.extracted_urls or result.extracted_handles or result.extracted_emails:
        lines.append("<b>🔗 Extracted Contacts &amp; Links</b>")
        if result.extracted_urls:
            urls = ", ".join(f"<code>{html.escape(u)}</code>" for u in result.extracted_urls[:5])
            lines.append(f"• Links: {urls}")
        if result.extracted_handles:
            handles = ", ".join(f"<code>{html.escape(h)}</code>" for h in result.extracted_handles[:5])
            lines.append(f"• Handles: {handles}")
        if result.extracted_emails:
            emails = ", ".join(f"<code>{html.escape(e)}</code>" for e in result.extracted_emails[:5])
            lines.append(f"• Emails: {emails}")
        lines.append("")

    if result.safe_checks:
        lines.append("<b>🛡️ How to Check Safely Before Acting</b>")
        for step in result.safe_checks:
            lines.append(f"• {html.escape(step)}")
        lines.append("")

    if result.do_not_do and result.risk_level != RiskLevel.LOW:
        lines.append("<b>⛔ What NOT to Do</b>")
        for item in result.do_not_do:
            lines.append(f"• {html.escape(item)}")

    return "\n".join(lines).strip()


def format_plain_text(result: AnalysisResult) -> str:
    """Format an AnalysisResult as readable plain text for CLI or logs."""
    badge = _RISK_BADGE[result.risk_level]
    lines: list[str] = [
        f"{badge} (Score: {result.score}/10)",
        result.summary,
        "",
    ]

    lines.append("Warning Signs Found:")
    if result.warning_signs:
        for idx, sign in enumerate(result.warning_signs, start=1):
            lines.append(f"  {idx}. [{sign.category}] {sign.title}")
            lines.append(f"     {sign.explanation}")
            if sign.evidence:
                lines.append(f"     Matched: {', '.join(sign.evidence)}")
    else:
        lines.append("  - No common fake-support red flags were matched.")
    lines.append("")

    if result.safe_checks:
        lines.append("How to Check Safely Before Acting:")
        for step in result.safe_checks:
            lines.append(f"  - {step}")
        lines.append("")

    if result.do_not_do and result.risk_level != RiskLevel.LOW:
        lines.append("What NOT to Do:")
        for item in result.do_not_do:
            lines.append(f"  - {item}")

    return "\n".join(lines).strip()
