"""Unit tests for the suspicious message analyzer and formatters."""

import unittest

from scam_checker import RiskLevel, analyze_message, format_plain_text, format_telegram_html


class TestAnalyzer(unittest.TestCase):
    def test_fake_support_otp_and_phishing_link_is_high_risk(self) -> None:
        msg = (
            "Dear customer, this is Official Support. Unauthorized login detected! "
            "Your account will be suspended within 2 hours. Send your verification code "
            "or verify at https://support-verify-account.xyz/login"
        )
        result = analyze_message(msg)
        self.assertEqual(result.risk_level, RiskLevel.HIGH)
        self.assertGreaterEqual(result.score, 6)
        categories = {w.category for w in result.warning_signs}
        self.assertIn("Secrets & Codes", categories)
        self.assertIn("Pressure Tactics", categories)
        self.assertIn("Impersonation", categories)
        self.assertIn("Suspicious Link", categories)
        self.assertTrue(any("official app" in step.lower() for step in result.safe_checks))

    def test_remote_access_and_free_email_is_high_risk(self) -> None:
        msg = (
            "Hello user, Billing Department here. Please install AnyDesk and share your "
            "screen with @support_agent99 or email helpdesk.verify@gmail.com."
        )
        result = analyze_message(msg)
        self.assertEqual(result.risk_level, RiskLevel.HIGH)
        categories = {w.category for w in result.warning_signs}
        self.assertIn("Remote Access", categories)
        self.assertIn("Unofficial Channel", categories)
        self.assertIn("@support_agent99", result.extracted_handles)
        self.assertIn("helpdesk.verify@gmail.com", result.extracted_emails)

    def test_shortened_url_and_payment_demand(self) -> None:
        msg = "Account locked! Pay a $20 unlock fee via gift card at https://bit.ly/3fake99"
        result = analyze_message(msg)
        self.assertEqual(result.risk_level, RiskLevel.HIGH)
        titles = [w.title for w in result.warning_signs]
        self.assertTrue(any("Shortened URL" in t for t in titles))
        self.assertTrue(any("payments" in t.lower() for t in titles))

    def test_fake_watch_video_job_scam_is_high_risk(self) -> None:
        msg = (
            "Part-time online job! Watch videos on YouTube and earn $50 per day. "
            "No experience needed, instant payout. Message @hr_tasks on Telegram."
        )
        result = analyze_message(msg)
        self.assertEqual(result.risk_level, RiskLevel.HIGH)
        categories = {w.category for w in result.warning_signs}
        self.assertIn("Fake Job / Task Scam", categories)
        self.assertTrue(any("deposit" in step.lower() for step in result.safe_checks))

    def test_triple_value_investment_scam_is_high_risk(self) -> None:
        for msg in (
            "Invest $100 today, wait a few hours, and you will get triple the value! Guaranteed profit.",
            "Invest $100, wait 3 hours, and get triple the value guaranteed!",
        ):
            result = analyze_message(msg)
            self.assertEqual(result.risk_level, RiskLevel.HIGH, msg=msg)
            categories = {w.category for w in result.warning_signs}
            self.assertIn("Investment / Doubling Scam", categories, msg=msg)
            self.assertTrue(any("double/triple" in step.lower() for step in result.safe_checks))

    def test_watch_video_short_phrase_is_high_risk(self) -> None:
        result = analyze_message("Watch video and get $50!")
        self.assertEqual(result.risk_level, RiskLevel.HIGH)
        categories = {w.category for w in result.warning_signs}
        self.assertIn("Fake Job / Task Scam", categories)

    def test_benign_notification_is_low_risk(self) -> None:
        msg = (
            "Hi Jordan, we updated your support ticket #48219. "
            "Please log in through our official mobile app to view the reply."
        )
        result = analyze_message(msg)
        self.assertEqual(result.risk_level, RiskLevel.LOW)
        self.assertTrue(len(result.safe_checks) >= 1)

    def test_forwarded_flag_adds_username_check(self) -> None:
        msg = "Please check your account status."
        result = analyze_message(msg, is_forwarded=True)
        categories = {w.category for w in result.warning_signs}
        self.assertIn("Forwarded Context", categories)

    def test_html_formatter_escapes_special_characters(self) -> None:
        msg = "Official Support <urgent> & verify at http://192.168.1.50/login"
        result = analyze_message(msg)
        html_out = format_telegram_html(result)
        self.assertIn("HIGH RISK", html_out)
        self.assertIn("<code>http://192.168.1.50/login</code>", html_out)
        self.assertNotIn("<urgent>", html_out)

    def test_plain_text_formatter(self) -> None:
        result = analyze_message("Send your seed phrase immediately!")
        text_out = format_plain_text(result)
        self.assertIn("HIGH RISK", text_out)
        self.assertIn("How to Check Safely Before Acting:", text_out)


if __name__ == "__main__":
    unittest.main()
