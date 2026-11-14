"""Telegram bot that helps customers spot fake-support and suspicious messages."""

from __future__ import annotations

import html
import logging
import os

from dotenv import load_dotenv
from telegram import InlineKeyboardButton, InlineKeyboardMarkup, LinkPreviewOptions, Update
from telegram.constants import ParseMode
from telegram.ext import (
    Application,
    CallbackQueryHandler,
    CommandHandler,
    ContextTypes,
    MessageHandler,
    filters,
)

from scam_checker import analyze_message, format_telegram_html

logging.basicConfig(
    format="%(asctime)s - %(name)s - %(levelname)s - %(message)s",
    level=logging.INFO,
)
logger = logging.getLogger(__name__)

NO_PREVIEW = LinkPreviewOptions(is_disabled=True)

EXAMPLE_MESSAGES = {
    "ex_scam_otp": (
        "Dear customer, this is Official Support. We detected an unauthorized login on "
        "your account and it will be suspended within 30 minutes. Reply with your 6-digit "
        "verification code or verify immediately at https://support-verify-account.xyz/login"
    ),
    "ex_scam_remote": (
        "Hello user, Billing Department here. To process your refund, please install "
        "AnyDesk and share your screen with @helper_support_team99 or email "
        "refunddesk.help@gmail.com."
    ),
    "ex_scam_job": (
        "Part-time online job! Watch YouTube videos and like posts to earn $80 per day. "
        "No experience needed, instant payout. Message @hr_task_manager on Telegram."
    ),
    "ex_scam_invest": (
        "Exclusive crypto offer: Invest $200, wait 3 hours, and you will get triple the "
        "value ($600) guaranteed! Risk-free profit, message us to deposit now."
    ),
    "ex_benign": (
        "Hi Alex, we updated your support ticket #48219. Please log in to your account "
        "through our mobile app to view the reply in your inbox."
    ),
}


def _examples_keyboard() -> InlineKeyboardMarkup:
    return InlineKeyboardMarkup([
        [
            InlineKeyboardButton("Test: Fake Support + OTP", callback_data="ex_scam_otp"),
            InlineKeyboardButton("Test: Remote Access Scam", callback_data="ex_scam_remote"),
        ],
        [
            InlineKeyboardButton("Test: Watch-Video Job Scam", callback_data="ex_scam_job"),
            InlineKeyboardButton("Test: Triple-Money Invest", callback_data="ex_scam_invest"),
        ],
        [
            InlineKeyboardButton("Test: Legitimate Notice", callback_data="ex_benign"),
            InlineKeyboardButton("Safe-Check Guide", callback_data="safe_guide"),
        ],
    ])


async def start_command(update: Update, context: ContextTypes.DEFAULT_TYPE) -> None:
    if not update.message:
        return
    text = (
        "<b>🛡️ Suspicious Message Checker</b>\n\n"
        "Received a suspicious message claiming to be <b>Support</b>, an <b>easy online job</b>, "
        "or a <b>high-return investment</b>? Forward it to me or paste the text here before you click, reply, or pay.\n\n"
        "<b>What I check for:</b>\n"
        "• Requests for OTP/2FA codes, passwords, or seed phrases\n"
        "• Fake urgency, account suspension threats, or remote-access requests\n"
        "• Fake job ads (e.g., watch videos / like posts for easy daily pay)\n"
        "• Investment scams promising to double or triple your money in hours\n"
        "• Shortened, unencrypted, or lookalike links\n\n"
        "Send a message now, or tap an example below to see how it works:"
    )
    await update.message.reply_text(
        text,
        parse_mode=ParseMode.HTML,
        reply_markup=_examples_keyboard(),
        link_preview_options=NO_PREVIEW,
    )


async def help_command(update: Update, context: ContextTypes.DEFAULT_TYPE) -> None:
    if not update.message:
        return
    text = (
        "<b>How to use this bot</b>\n\n"
        "1. <b>Forward</b> a suspicious message directly to this chat, OR\n"
        "2. <b>Paste</b> the message text (or use <code>/check &lt;message&gt;</code>).\n\n"
        "<b>Commands:</b>\n"
        "• /start — Welcome &amp; quick examples\n"
        "• /examples — Try sample scam vs. legitimate messages\n"
        "• /check &lt;text&gt; — Analyze a pasted message\n"
        "• /help — Show this help message"
    )
    await update.message.reply_text(
        text,
        parse_mode=ParseMode.HTML,
        link_preview_options=NO_PREVIEW,
    )


async def examples_command(update: Update, context: ContextTypes.DEFAULT_TYPE) -> None:
    if not update.message:
        return
    await update.message.reply_text(
        "Tap a sample message below to see the warning signs and safe-check steps:",
        reply_markup=_examples_keyboard(),
        link_preview_options=NO_PREVIEW,
    )


async def check_command(update: Update, context: ContextTypes.DEFAULT_TYPE) -> None:
    if not update.message:
        return
    text = " ".join(context.args).strip() if context.args else ""
    if not text:
        await update.message.reply_text(
            "Please include the message after <code>/check</code>, or just paste/forward it directly.",
            parse_mode=ParseMode.HTML,
        )
        return

    result = analyze_message(text, is_forwarded=False)
    await update.message.reply_text(
        format_telegram_html(result),
        parse_mode=ParseMode.HTML,
        link_preview_options=NO_PREVIEW,
    )


async def handle_message(update: Update, context: ContextTypes.DEFAULT_TYPE) -> None:
    message = update.message
    if not message:
        return

    text = (message.text or message.caption or "").strip()
    if not text:
        await message.reply_text(
            "Please forward or paste the text of the suspicious message so I can inspect it."
        )
        return

    is_forwarded = message.forward_origin is not None
    result = analyze_message(text, is_forwarded=is_forwarded)
    await message.reply_text(
        format_telegram_html(result),
        parse_mode=ParseMode.HTML,
        link_preview_options=NO_PREVIEW,
    )


async def handle_callback(update: Update, context: ContextTypes.DEFAULT_TYPE) -> None:
    query = update.callback_query
    if not query or not query.data:
        return
    await query.answer()

    if query.data == "safe_guide":
        guide = (
            "<b>🛡️ 5-Step Safe Verification Checklist</b>\n\n"
            "1. <b>Pause</b> — Scammers rely on panic and tight deadlines.\n"
            "2. <b>Never use their link</b> — Open the official app or type the website yourself.\n"
            "3. <b>Check the real @username</b> — Display names and logos are easy to fake.\n"
            "4. <b>Never share secrets</b> — Real support never needs your OTP, password, or seed phrase.\n"
            "5. <b>Confirm in-app</b> — Check your official notifications or open a ticket inside the app."
        )
        if query.message:
            await query.message.reply_text(
                guide,
                parse_mode=ParseMode.HTML,
                link_preview_options=NO_PREVIEW,
            )
        return

    sample_text = EXAMPLE_MESSAGES.get(query.data)
    if sample_text and query.message:
        result = analyze_message(sample_text, is_forwarded=False)
        response = (
            f"<b>Sample Message Checked:</b>\n"
            f"<blockquote>{html.escape(sample_text)}</blockquote>\n\n"
            f"{format_telegram_html(result)}"
        )
        await query.message.reply_text(
            response,
            parse_mode=ParseMode.HTML,
            link_preview_options=NO_PREVIEW,
        )


def main() -> None:
    load_dotenv()
    token = os.getenv("TELEGRAM_BOT_TOKEN")
    if not token:
        raise RuntimeError(
            "TELEGRAM_BOT_TOKEN is not set. Copy .env.example to .env and add your bot token."
        )

    app = Application.builder().token(token).build()
    app.add_handler(CommandHandler("start", start_command))
    app.add_handler(CommandHandler("help", help_command))
    app.add_handler(CommandHandler("examples", examples_command))
    app.add_handler(CommandHandler("check", check_command))
    app.add_handler(CallbackQueryHandler(handle_callback))
    app.add_handler(MessageHandler((filters.TEXT | filters.CAPTION) & ~filters.COMMAND, handle_message))

    logger.info("Starting Telegram scam-checker bot...")
    app.run_polling(allowed_updates=Update.ALL_TYPES)


if __name__ == "__main__":
    main()
