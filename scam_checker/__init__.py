"""Suspicious message analyzer package for the Telegram scam-checker bot."""

from .analyzer import AnalysisResult, RiskLevel, WarningSign, analyze_message
from .formatter import format_telegram_html, format_plain_text

__all__ = [
    "AnalysisResult",
    "RiskLevel",
    "WarningSign",
    "analyze_message",
    "format_telegram_html",
    "format_plain_text",
]
