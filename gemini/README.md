# Telegram Suspicious Message Checker Bot

A Telegram bot that helps customers recognize suspicious "fake support" messages, highlights specific warning signs, and gives clear, safe verification steps before they click, reply, or share any information.

## Features

- **Fake-Support Red Flag Detection** (`scam_checker/analyzer.py`):
  - **Secrets & Codes**: Detects requests for OTP/2FA codes, passwords, PINs, or wallet seed phrases.
  - **Pressure Tactics**: Flags artificial urgency, countdowns, and account-suspension threats.
  - **Suspicious Links**: Inspects URLs for `http://`, raw IP addresses, punycode (`xn--`), URL shorteners (`bit.ly`, `tinyurl.com`, etc.), high-risk TLDs (`.xyz`, `.support`, `.top`, etc.), and hyphenated lookalike support domains.
  - **Remote Access & Payments**: Flags requests to install AnyDesk/TeamViewer, share screens, buy gift cards, or pay "verification/unlock" fees.
  - **Fake Job / Task Scams**: Detects offers paying easy money to watch videos, like posts, or complete simple tasks.
  - **Investment / Doubling Scams**: Flags promises to double or triple your money in a few hours or guarantee risk-free returns.
  - **Impersonation & Off-Channel Cues**: Spots generic greetings, "Official Support" claims paired with personal emails (`@gmail.com`, etc.), and forwarded-message impersonation risks.
- **Safe-Check Guidance**: Returns actionable verification steps tailored to what was found, plus a "What NOT to Do" guardrail list.
- **Link-Preview Protection**: Disables Telegram link previews on bot replies so suspicious URLs aren't fetched.
- **Interactive Examples & Local CLI**: Includes `/examples` inline buttons in Telegram and a zero-dependency `cli.py` for local testing.

## Project Structure

```text
telegram-scam-checker-bot/
├── bot.py                  # Telegram bot entrypoint (python-telegram-bot v21+)
├── cli.py                  # Local CLI to test messages without a bot token
├── scam_checker/
│   ├── __init__.py
│   ├── analyzer.py         # Core rule-based scam detection engine (stdlib only)
│   └── formatter.py        # Telegram HTML & plain-text formatters
├── tests/
│   └── test_analyzer.py    # Unit tests (unittest)
├── requirements.txt
└── .env.example
```

## Setup & Run

### 1. Create a Telegram Bot Token
1. Open Telegram and message **@BotFather**.
2. Send `/newbot`, choose a name and username, and copy the bot token.

### 2. Install Dependencies
```bash
cd /home/honor/.gemini/antigravity/scratch/telegram-scam-checker-bot
python3 -m venv .venv
source .venv/bin/activate
pip install -r requirements.txt
```

### 3. Configure & Start the Bot
```bash
cp .env.example .env
# Edit .env and paste your TELEGRAM_BOT_TOKEN
python3 bot.py
```

## Test Locally (No Token Needed)

Run the unit tests:
```bash
python3 -m unittest discover -s tests
```

Or test any message from the command line:
```bash
python3 cli.py "Official Support: your account will be locked in 1 hour. Send your OTP or verify at https://support-verify.xyz"
```

## Deploy 24/7

Because `bot.py` uses Telegram long-polling (`run_polling`), it does not need an open inbound HTTP port—just a background worker process with `TELEGRAM_BOT_TOKEN` set.

### Option 1: Docker
```bash
cd /home/honor/.gemini/antigravity/scratch/telegram-scam-checker-bot
docker build -t telegram-scam-checker-bot .
docker run -d --name scam-checker-bot --restart unless-stopped --env-file .env telegram-scam-checker-bot
```

### Option 2: Railway / Render (PaaS)
1. Push this folder to a GitHub repository (make sure `.env` is **not** committed).
2. Create a new **Background Worker** (Render) or **Service** (Railway) connected to the repo.
3. It will use `Procfile` (`worker: python bot.py`) or `Dockerfile` automatically.
4. Add `TELEGRAM_BOT_TOKEN` in the platform's Environment Variables settings and deploy.

### Option 3: Linux VPS (`systemd`)
Create `/etc/systemd/system/scam-checker-bot.service`:
```ini
[Unit]
Description=Telegram Scam Checker Bot
After=network.target

[Service]
Type=simple
WorkingDirectory=/path/to/telegram-scam-checker-bot
EnvironmentFile=/path/to/telegram-scam-checker-bot/.env
ExecStart=/path/to/telegram-scam-checker-bot/.venv/bin/python bot.py
Restart=always
RestartSec=5

[Install]
WantedBy=multi-user.target
```
Then enable and start it:
```bash
sudo systemctl daemon-reload
sudo systemctl enable --now scam-checker-bot
```
