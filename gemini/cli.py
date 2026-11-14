"""Local CLI to test the suspicious message analyzer without a Telegram token."""

from __future__ import annotations

import argparse
import sys

from scam_checker import analyze_message, format_plain_text


def main() -> int:
    parser = argparse.ArgumentParser(
        description="Check a suspicious message for fake-support scam indicators."
    )
    parser.add_argument(
        "message",
        nargs="*",
        help="Message text to analyze. If omitted, reads from stdin.",
    )
    parser.add_argument(
        "--forwarded",
        action="store_true",
        help="Simulate a forwarded Telegram message.",
    )
    args = parser.parse_args()

    text = " ".join(args.message).strip() if args.message else sys.stdin.read().strip()
    result = analyze_message(text, is_forwarded=args.forwarded)
    print(format_plain_text(result))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
