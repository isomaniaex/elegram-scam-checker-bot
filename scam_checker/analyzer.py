"""Rule-based suspicious message analyzer focused on fake-support scams."""

from __future__ import annotations

import re
from dataclasses import dataclass, field
from enum import Enum
from urllib.parse import urlparse


class RiskLevel(str, Enum):
    LOW = "LOW"
    MEDIUM = "MEDIUM"
    HIGH = "HIGH"


@dataclass(frozen=True)
class WarningSign:
    """A single suspicious indicator detected in a message."""

    category: str
    title: str
    explanation: str
    severity: int  # 1 (minor) to 3 (critical)
    evidence: tuple[str, ...] = ()


@dataclass
class AnalysisResult:
    """Structured result of analyzing a suspicious message."""

    risk_level: RiskLevel
    score: int
    summary: str
    warning_signs: list[WarningSign] = field(default_factory=list)
    safe_checks: list[str] = field(default_factory=list)
    do_not_do: list[str] = field(default_factory=list)
    extracted_urls: list[str] = field(default_factory=list)
    extracted_handles: list[str] = field(default_factory=list)
    extracted_emails: list[str] = field(default_factory=list)


URL_REGEX = re.compile(
    r"(?:https?://|www\.)[^\s<>\"'\)\]]+",
    re.IGNORECASE,
)
DOMAIN_LIKE_REGEX = re.compile(
    r"\b(?:[a-z0-9-]+\.)+(?:com|net|org|io|co|xyz|top|click|support|help|tk|ml|ga|cf|gq|icu|vip|buzz|info|app|me)(?:/[^\s<>\"'\)\]]*)?\b",
    re.IGNORECASE,
)
HANDLE_REGEX = re.compile(r"(?<!\w)@[a-zA-Z0-9_]{4,32}\b")
EMAIL_REGEX = re.compile(r"\b[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}\b")
IPV4_HOST_REGEX = re.compile(r"^\d{1,3}(?:\.\d{1,3}){3}$")

SHORTENER_DOMAINS = {
    "bit.ly",
    "tinyurl.com",
    "t.co",
    "rb.gy",
    "cutt.ly",
    "is.gd",
    "shorturl.at",
    "ow.ly",
    "buff.ly",
    "tiny.cc",
    "rebrand.ly",
    "goo.gl",
}

SUSPICIOUS_TLDS = {
    "xyz",
    "top",
    "click",
    "support",
    "help",
    "tk",
    "ml",
    "ga",
    "cf",
    "gq",
    "icu",
    "vip",
    "buzz",
}

FREE_EMAIL_DOMAINS = {
    "gmail.com",
    "yahoo.com",
    "outlook.com",
    "hotmail.com",
    "proton.me",
    "protonmail.com",
    "icloud.com",
    "aol.com",
    "mail.com",
}

# (pattern, label) pairs for common fake-support tactics
SECRET_PATTERNS = [
    (re.compile(r"\b(?:otp|one[- ]time[- ]pass(?:code|word)|2fa|two[- ]factor|verification code|security code|login code|auth(?:entication)? code)\b", re.I), "asks for a verification/OTP code"),
    (re.compile(r"\b(?:password|passcode|pin\s*number|cvv|card\s*pin|ssn|social security)\b", re.I), "asks for password, PIN, or card details"),
    (re.compile(r"\b(?:seed\s*phrase|recovery\s*phrase|secret\s*phrase|mnemonic|private\s*key|12[- ]word|24[- ]word)\b", re.I), "asks for a wallet seed phrase or private key"),
]

URGENCY_PATTERNS = [
    (re.compile(r"\b(?:urgent|immediately|right now|asap|within\s+\d+\s*(?:minutes?|hours?)|final\s+(?:warning|notice)|last\s+chance)\b", re.I), "pressures you to act immediately"),
    (re.compile(r"\b(?:account|wallet|profile|card)\s+(?:will be|has been|is)\s+(?:suspended|locked|frozen|terminated|deleted|restricted|disabled|compromised)\b", re.I), "threatens account suspension or lock"),
    (re.compile(r"\b(?:unauthorized|suspicious)\s+(?:login|activity|access|transaction|attempt)\b", re.I), "claims unauthorized activity to trigger panic"),
]

IMPERSONATION_PATTERNS = [
    (re.compile(r"\b(?:official\s+support|customer\s+support|support\s+team|security\s+team|help\s*desk|verification\s+(?:team|department)|billing\s+department|account\s+recovery\s+team|telegram\s+support|admin\s+support)\b", re.I), "claims to be official support or security"),
    (re.compile(r"\b(?:dear\s+(?:customer|user|member|valued\s+user)|hello\s+user)\b", re.I), "uses a generic greeting instead of your name"),
]

REMOTE_ACCESS_PATTERNS = [
    (re.compile(r"\b(?:anydesk|teamviewer|quicksupport|rustdesk|ultraviewer|ammyy|screen\s*share|share\s+your\s+screen|remote\s+(?:access|control|desktop))\b", re.I), "asks for remote access or screen sharing"),
]

PAYMENT_PATTERNS = [
    (re.compile(r"\b(?:gift\s*card|itunes\s*card|google\s*play\s*card|steam\s*card|prepaid\s*card)\b", re.I), "requests payment via gift cards"),
    (re.compile(r"\b(?:send|transfer|deposit)\s+(?:crypto|bitcoin|btc|eth|usdt|usdc|funds|money|fee)\b", re.I), "asks you to send money or crypto"),
    (re.compile(r"\b(?:verification\s+fee|unlock\s+fee|refundable\s+deposit|safe\s+wallet|escrow\s+wallet)\b", re.I), "mentions a verification fee or 'safe wallet'"),
]

OFF_CHANNEL_PATTERNS = [
    (re.compile(r"\b(?:message\s+(?:me|us)\s+on|contact\s+(?:us|support)\s+(?:on|via)|reach\s+out\s+on|reply\s+on)\s+(?:telegram|whatsapp|signal|viber)\b", re.I), "pushes you to continue on a separate messaging app"),
]

JOB_TASK_PATTERNS = [
    (re.compile(r"\b(?:watch(?:ing)?\s+(?:\d+\s+)?(?:videos?|youtube|tiktok|reels?)|like\s+(?:\d+\s+)?(?:videos?|posts?)|subscribe\s+to\s+(?:\d+\s+)?channels?|rate\s+(?:products?|apps?)|simple\s+(?:online\s+)?tasks?)\b.{0,60}\b(?:earn|get\s+(?:paid|money|cash|reward|\$?\d+)|make\s+money|cash|salary|commission|reward|\$\d+)\b", re.I | re.S), "offers money for watching videos or doing simple clicks"),
    (re.compile(r"\b(?:earn|make|get)\s+(?:\$?\d+(?:[.,]\d+)?\s*(?:per|a|every)\s*(?:day|hour|video|task|click)|easy\s+money|daily\s+(?:income|salary|payout))\b", re.I), "promises easy daily income for minimal effort"),
    (re.compile(r"\b(?:part[- ]time\s+(?:online\s+)?job|remote\s+task|work\s+from\s+home)\b.{0,60}\b(?:no\s+experience|instant\s+pay(?:out)?|vip\s+(?:level|task)|recharge|prepaid\s+task)\b", re.I | re.S), "uses classic task-scam job wording"),
]

INVESTMENT_PATTERNS = [
    (re.compile(r"\b(?:double|triple|quadruple|multiply|2x|3x|4x|5x|10x)\s+(?:the\s+|your\s+|initial\s+|original\s+)?(?:money|investment|deposit|funds|crypto|value|amount|profit|returns?)\b", re.I), "promises to double or triple your money"),
    (re.compile(r"\b(?:invest|deposit|put\s+in|send)\b.{0,80}\b(?:wait\s+(?:for\s+)?(?:a\s+few\s+|a\s+couple\s+(?:of\s+)?|\d+\s+)?(?:hours?|hrs?|minutes?|mins?|days?)|(?:in|within)\s+(?:just\s+)?\d+\s*(?:hours?|hrs?|minutes?|mins?))\b.{0,80}\b(?:get|receive|earn|back|triple|double|quadruple|profit|return|payout)\b", re.I | re.S), "promises huge returns after waiting a short time"),
    (re.compile(r"\b(?:guaranteed\s+(?:profit|returns?|roi|income)|(?:profit|returns?|value|payout|income)\s+guaranteed|risk[- ]free\s+(?:investment|trading|profit|returns?)|instant\s+(?:profit|roi|returns?)|100%\s+(?:profit|guaranteed|safe\s+return))\b", re.I), "promises guaranteed or risk-free returns"),
    (re.compile(r"\b\d{2,4}%\s+(?:profit|return|returns|roi)\s+(?:in|within|every|per)\s+(?:\d+\s*)?(?:hours?|hrs?|days?|week)\b", re.I), "advertises unrealistic percentage returns"),
]


def _extract_urls(text: str) -> list[str]:
    urls: list[str] = []
    seen: set[str] = set()

    for match in URL_REGEX.findall(text):
        cleaned = match.rstrip(".,;:!?")
        if cleaned not in seen:
            seen.add(cleaned)
            urls.append(cleaned)

    # Also catch bare domains like "support-verify-account.xyz/login"
    for match in DOMAIN_LIKE_REGEX.findall(text):
        cleaned = match.rstrip(".,;:!?")
        # Skip if it looks like part of an email address or already captured
        if any(cleaned in existing for existing in seen):
            continue
        idx = text.find(cleaned)
        if idx > 0 and text[idx - 1] == "@":
            continue
        seen.add(cleaned)
        urls.append(cleaned)

    return urls


def _inspect_url(raw_url: str) -> list[tuple[str, str, int]]:
    """Return list of (title, explanation, severity) issues for a URL."""
    issues: list[tuple[str, str, int]] = []
    normalized = raw_url if raw_url.lower().startswith(("http://", "https://")) else f"http://{raw_url}"
    parsed = urlparse(normalized)
    host = (parsed.hostname or "").lower()

    if not host:
        return issues

    if raw_url.lower().startswith("http://"):
        issues.append((
            "Unencrypted HTTP link",
            f"The link `{raw_url}` uses `http://` instead of `https://`, which legitimate support portals rarely use for login or verification.",
            2,
        ))

    if IPV4_HOST_REGEX.match(host):
        issues.append((
            "Raw IP address link",
            f"The link points to a raw IP address (`{host}`) instead of an official company domain.",
            3,
        ))

    if "xn--" in host:
        issues.append((
            "Lookalike punycode domain",
            f"The domain `{host}` uses punycode (`xn--`), which is often used to spoof lookalike characters.",
            3,
        ))

    if host in SHORTENER_DOMAINS or any(host.endswith(f".{d}") for d in SHORTENER_DOMAINS):
        issues.append((
            "Shortened URL hides destination",
            f"The shortened link (`{host}`) hides where it actually leads until you click it.",
            2,
        ))

    tld = host.rsplit(".", 1)[-1] if "." in host else ""
    if tld in SUSPICIOUS_TLDS:
        issues.append((
            "High-risk or unusual domain ending",
            f"The domain `{host}` ends in `.{tld}`, a TLD frequently abused in phishing campaigns.",
            2,
        ))

    # Check for deceptive hyphenated support/verify domains like "paypal-support-verify.com"
    support_words = ("support", "verify", "security", "login", "account", "recover", "billing", "helpdesk")
    hyphen_parts = host.split(".")[0].split("-")
    if len(hyphen_parts) >= 2 and any(w in hyphen_parts for w in support_words):
        issues.append((
            "Suspicious lookalike support domain",
            f"The domain `{host}` combines hyphens with support/verification words — a classic phishing pattern.",
            2,
        ))

    return issues


def _collect_matches(text: str, patterns: list[tuple[re.Pattern[str], str]]) -> list[str]:
    hits: list[str] = []
    for pattern, _ in patterns:
        for match in pattern.finditer(text):
            snippet = match.group(0).strip()
            if snippet.lower() not in {h.lower() for h in hits}:
                hits.append(snippet)
    return hits


def analyze_message(text: str, *, is_forwarded: bool = False) -> AnalysisResult:
    """Analyze a message for fake-support scam indicators and safe verification steps."""
    cleaned = text.strip()
    if not cleaned:
        return AnalysisResult(
            risk_level=RiskLevel.LOW,
            score=0,
            summary="No message text was provided to check.",
            safe_checks=["Paste or forward the full suspicious message so I can inspect it."],
        )

    warnings: list[WarningSign] = []
    urls = _extract_urls(cleaned)
    emails = EMAIL_REGEX.findall(cleaned)
    # Exclude email domains from @handle matches
    handles = [
        h for h in HANDLE_REGEX.findall(cleaned)
        if not any(h in email for email in emails)
    ]

    # 1. Credential / OTP / Seed phrase harvesting
    secret_hits = _collect_matches(cleaned, SECRET_PATTERNS)
    if secret_hits:
        warnings.append(WarningSign(
            category="Secrets & Codes",
            title="Asks for sensitive codes, passwords, or keys",
            explanation=(
                "Real support teams NEVER ask for your password, 2FA/OTP code, PIN, "
                "or crypto recovery/seed phrase."
            ),
            severity=3,
            evidence=tuple(secret_hits[:4]),
        ))

    # 2. Remote access / screen sharing
    remote_hits = _collect_matches(cleaned, REMOTE_ACCESS_PATTERNS)
    if remote_hits:
        warnings.append(WarningSign(
            category="Remote Access",
            title="Requests remote access or screen sharing",
            explanation=(
                "Scammers use remote-control apps or screen sharing to view your codes "
                "or take over your device and accounts."
            ),
            severity=3,
            evidence=tuple(remote_hits[:4]),
        ))

    # 3. Payment / gift card / crypto demands
    payment_hits = _collect_matches(cleaned, PAYMENT_PATTERNS)
    if payment_hits:
        warnings.append(WarningSign(
            category="Payment Demand",
            title="Asks for unusual payments, fees, or transfers",
            explanation=(
                "Legitimate support will never ask you to pay an 'unlock/verification fee', "
                "buy gift cards, or move funds to a 'safe wallet'."
            ),
            severity=3,
            evidence=tuple(payment_hits[:4]),
        ))

    # 4. Urgency & fear tactics
    urgency_hits = _collect_matches(cleaned, URGENCY_PATTERNS)
    if urgency_hits:
        warnings.append(WarningSign(
            category="Pressure Tactics",
            title="Creates artificial urgency or threats",
            explanation=(
                "Threatening immediate account suspension or unauthorized access is used "
                "to make you act fast before verifying."
            ),
            severity=2,
            evidence=tuple(urgency_hits[:4]),
        ))

    # 5. Impersonation cues
    impersonation_hits = _collect_matches(cleaned, IMPERSONATION_PATTERNS)
    if impersonation_hits:
        warnings.append(WarningSign(
            category="Impersonation",
            title="Claims to be official support or uses generic phrasing",
            explanation=(
                "Anyone can set their display name or bio to 'Official Support'. "
                "Legitimate support rarely DMs you out of the blue."
            ),
            severity=1,
            evidence=tuple(impersonation_hits[:4]),
        ))

    # 6. Off-channel / free email contact
    off_channel_hits = _collect_matches(cleaned, OFF_CHANNEL_PATTERNS)
    free_emails = [
        e for e in emails
        if e.rsplit("@", 1)[-1].lower() in FREE_EMAIL_DOMAINS
    ]
    if off_channel_hits or (impersonation_hits and free_emails):
        evidence = tuple((off_channel_hits + free_emails)[:4])
        warnings.append(WarningSign(
            category="Unofficial Channel",
            title="Directs you to an unofficial contact channel",
            explanation=(
                "Real company support uses official in-app tickets or verified company "
                "domains, not personal Gmail/Outlook addresses or random chat handles."
            ),
            severity=2,
            evidence=evidence,
        ))

    # 7. Fake job / paid-to-watch-video task scams
    job_hits = _collect_matches(cleaned, JOB_TASK_PATTERNS)
    if job_hits:
        warnings.append(WarningSign(
            category="Fake Job / Task Scam",
            title="Promises easy money for simple online tasks",
            explanation=(
                "Task scams lure people with easy pay for watching videos, liking posts, "
                "or rating products, then pressure you to deposit your own money to unlock "
                "higher 'VIP' tasks or withdraw earnings."
            ),
            severity=3,
            evidence=tuple(job_hits[:4]),
        ))

    # 8. Investment / money-doubling scams
    investment_hits = _collect_matches(cleaned, INVESTMENT_PATTERNS)
    if investment_hits:
        warnings.append(WarningSign(
            category="Investment / Doubling Scam",
            title="Promises guaranteed or rapid multiplied returns",
            explanation=(
                "No legitimate investment can triple your money in a few hours or guarantee "
                "risk-free profits. Scammers often show fake profit dashboards or small initial "
                "payouts to convince you to deposit more."
            ),
            severity=3,
            evidence=tuple(investment_hits[:4]),
        ))

    # 9. URL inspection
    url_issue_seen: set[str] = set()
    for url in urls:
        for title, explanation, severity in _inspect_url(url):
            key = f"{title}:{url}"
            if key not in url_issue_seen:
                url_issue_seen.add(key)
                warnings.append(WarningSign(
                    category="Suspicious Link",
                    title=title,
                    explanation=explanation,
                    severity=severity,
                    evidence=(url,),
                ))

    if urls and not any(w.category == "Suspicious Link" for w in warnings):
        warnings.append(WarningSign(
            category="Unverified Link",
            title="Contains a link you should verify independently",
            explanation=(
                "Even if a link looks clean at first glance, attackers can use lookalike "
                "domains. Never log in through a link sent in an unexpected message."
            ),
            severity=1,
            evidence=tuple(urls[:3]),
        ))

    if is_forwarded:
        warnings.append(WarningSign(
            category="Forwarded Context",
            title="Forwarded message — check the original sender's @username",
            explanation=(
                "Scammers often copy a company's logo and set their display name to "
                "'Support'. Always check the actual @username or phone number, not the display name."
            ),
            severity=1,
        ))

    # Score calculation
    raw_score = sum(w.severity * 2 for w in warnings)
    # Boost if impersonation is combined with urgency, links, or secret requests
    has_impersonation = bool(impersonation_hits)
    has_high_risk_ask = bool(secret_hits or remote_hits or payment_hits)
    if has_impersonation and (urgency_hits or urls or has_high_risk_ask):
        raw_score += 2
    score = min(raw_score, 10)

    if any(w.severity >= 3 for w in warnings) or score >= 6:
        risk_level = RiskLevel.HIGH
        summary = (
            "High risk: This message shows strong signs of a scam (such as fake support, "
            "a fake job/task offer, or a get-rich-quick investment). Do not click links, "
            "share codes, or send money."
        )
    elif score >= 3 or len(warnings) >= 2:
        risk_level = RiskLevel.MEDIUM
        summary = (
            "Medium risk: This message has suspicious patterns common in online scams. "
            "Verify independently through official channels before taking any action."
        )
    else:
        risk_level = RiskLevel.LOW
        summary = (
            "Low risk: No obvious scam red flags were detected, but always verify "
            "unexpected messages through the official app or website."
        )

    safe_checks = _build_safe_checks(
        has_urls=bool(urls),
        has_secrets=bool(secret_hits),
        has_remote=bool(remote_hits),
        has_payment=bool(payment_hits),
        has_handles=bool(handles),
        has_job_scam=bool(job_hits),
        has_investment_scam=bool(investment_hits),
    )

    do_not_do = [
        "Do NOT click links or download attachments from the message.",
        "Do NOT share 2FA/OTP codes, passwords, PINs, or seed phrases.",
        "Do NOT install remote-access tools (AnyDesk, TeamViewer) for anyone.",
        "Do NOT pay deposits, 'recharge' fees, or invest money based on promised rapid returns.",
        "Do NOT trust the sender's display name, profile photo, or profit screenshots alone.",
    ]

    return AnalysisResult(
        risk_level=risk_level,
        score=score,
        summary=summary,
        warning_signs=warnings,
        safe_checks=safe_checks,
        do_not_do=do_not_do,
        extracted_urls=urls,
        extracted_handles=handles,
        extracted_emails=emails,
    )


def _build_safe_checks(
    *,
    has_urls: bool,
    has_secrets: bool,
    has_remote: bool,
    has_payment: bool,
    has_handles: bool,
    has_job_scam: bool = False,
    has_investment_scam: bool = False,
) -> list[str]:
    checks = [
        "Open the company's official app or type its official website address yourself — never use links from the message.",
        "Check your account notifications or support tickets inside the official app to see if any issue actually exists.",
        "Verify the sender's exact @username, email domain, or phone number against the company's official 'Contact Us' page.",
    ]
    if has_urls:
        checks.append(
            "Inspect the full domain carefully (check for extra hyphens, misspellings, or unusual endings like .xyz or .support)."
        )
    if has_handles:
        checks.append(
            "On Telegram, tap the sender's profile and check their real @username and whether they have an official verified checkmark."
        )
    if has_secrets:
        checks.append(
            "If you already shared a code or password, change your password immediately from the official app and revoke active sessions."
        )
    if has_remote:
        checks.append(
            "If someone asked for screen sharing or remote control, end the conversation immediately — real support does not need full device control."
        )
    if has_payment:
        checks.append(
            "Never pay to 'unlock' an account or verify ownership; contact your bank or platform through their official app if you're unsure."
        )
    if has_job_scam:
        checks.append(
            "Legitimate employers never ask you to pay a deposit, 'recharge', or buy 'VIP' tiers to receive wages. Verify any job directly on the company's official careers page."
        )
    if has_investment_scam:
        checks.append(
            "Treat any promise to double/triple your money in hours or guarantee risk-free profits as a scam, and check whether any financial platform is licensed by a real regulator."
        )
    return checks
