# AI-assisted implementation: written with AI assistance and reviewed by the
# project author.

import unittest
from pathlib import Path
import re

from app.ui.presentation import (
    NON_URL_GUIDANCE,
    get_api_error_message,
    get_decision_display,
    get_display_explanation,
    get_qr_content_display,
    get_result_presentation,
    get_score_evidence_display,
    get_url_vet_display,
    get_url_vet_evidence_display,
    get_unverifiable_payment_message,
)


def two_score_result() -> dict:
    return {
        "content_type": "url",
        "hostname": "example.com",
        "analysis_status": "Complete",
        "assessment_outcome": "Review required",
        "analysis": {
            "score": 90.0,
            "risk_score": 90.0,
            "level": "High",
            "reasons": ["url.vet found a destination risk signal."],
            "model_name": "url.vet",
            "model_version": "urlvet-test-v1",
            "trust_score": 25.0,
            "verdict": "Safe",
            "judgement_score": 20.0,
            "judgement_reasons": ["The local model found fewer lexical signals."],
            "judgement_model_name": "LogisticRegression",
            "judgement_model_version": "url-risk-lr-test-v1",
        },
        "decision": {
            "policy_version": "phase3-decision-policy-v1",
            "policy_status": "provisional",
            "benchmark": 79.0,
            "agreement_margin": 1.0,
            "thresholds": {
                "low_medium": 62.0,
                "medium_high": 79.0,
                "high_dangerous": 100.0,
            },
            "suspicion_level": "High suspicion",
            "conclusion": "Partially suspicious",
            "confidence_level": "Low",
            "confidence_reason": (
                "The url.vet risk score and local judgement score disagree around "
                "the benchmark B=79."
            ),
            "decision_reasons": [
                "url.vet risk score 90 reached B=79.",
                "Local judgement score 20 stayed below B=79.",
            ],
            "risk_score_level": "High suspicion",
            "judgement_score_level": "Low suspicion",
            "risk_vote_suspicious": True,
            "judgement_vote_suspicious": False,
            "adverse_verdict": None,
        },
        "checks": [],
    }


class E1US1PresentationTests(unittest.TestCase):
    def assert_non_url_guidance(self, display: dict) -> None:
        self.assertTrue(display["is_non_url"])
        self.assertEqual(display["guidance"], NON_URL_GUIDANCE)
        self.assertEqual(
            display["guidance"],
            "This is not a valid URL. Review the decoded content before deciding whether to trust it.",
        )

    def test_invalid_image_error_is_recoverable_plain_english(self) -> None:
        message = get_api_error_message(400)
        self.assertIn("Try a clearer image", message)

    def test_oversized_error_explains_recovery(self) -> None:
        message = get_api_error_message(413)
        self.assertIn("5 MiB", message)
        self.assertIn("smaller image", message)

    def test_display_explanation_matches_api_reason_and_version_fields(self) -> None:
        analysis = {
            "model_version": "url-risk-lr-2026.07.29",
            "reasons": ["one", "two", "three", "four"],
        }
        display = get_display_explanation(analysis)
        self.assertEqual(display["model_version"], analysis["model_version"])
        self.assertEqual(display["reasons"], ["one", "two", "three"])

    def test_unverifiable_payment_message_requires_confirmation(self) -> None:
        message = get_unverifiable_payment_message()
        self.assertIn("Unverifiable", message)
        self.assertIn("confirm the payee and amount", message)

    def test_url_vet_display_includes_verdict_and_trust_score(self) -> None:
        display = get_url_vet_display(
            {
                "model_name": "url.vet",
                "verdict": "Safe",
                "trust_score": 100,
            }
        )
        self.assertEqual(display, "url.vet verdict: Safe; trust score: 100/100.")

    def test_url_vet_display_is_hidden_for_non_url_analysis(self) -> None:
        self.assertIsNone(
            get_url_vet_display({"model_name": "url-risk-lr", "verdict": "Safe"})
        )

    def test_partial_url_vet_evidence_is_displayable_when_analysis_is_incomplete(self) -> None:
        display = get_url_vet_evidence_display(
            {
                "analysis": None,
                "checks": [
                    {
                        "check_id": "url_vet",
                        "status": "incomplete",
                        "summary": "url.vet reported an incomplete analysis.",
                        "details": {
                            "risk_score": 5.0,
                            "risk_level": "Low",
                            "trust_score": 100.0,
                            "verdict": "Safe",
                            "reasons": ["Long-standing domain history."],
                        },
                    }
                ],
            }
        )

        self.assertEqual(display["title"], "Partial url.vet evidence")
        self.assertEqual(display["risk_score"], "5 / 100")
        self.assertEqual(display["risk_level"], "Low")
        self.assertEqual(display["verdict"], "Safe")
        self.assertEqual(display["trust_score"], "100 / 100")
        self.assertIn("incomplete", display["notice"].casefold())
        self.assertEqual(display["reasons"], ["Long-standing domain history."])

    def test_partial_url_vet_analysis_is_labelled_as_partial(self) -> None:
        display = get_url_vet_evidence_display(
            {
                "analysis": {
                    "model_name": "url.vet",
                    "risk_score": 30.0,
                    "risk_level": "Low",
                    "trust_score": 100.0,
                    "verdict": "Safe",
                    "reasons": ["Partial evidence."],
                    "url_vet_partial": True,
                },
                "checks": [],
            }
        )

        self.assertEqual(display["title"], "Partial url.vet evidence")
        self.assertEqual(display["status"], "warning")
        self.assertIn("incomplete", display["notice"].casefold())

    def test_decision_display_includes_conflict_policy_and_all_four_ranges(self) -> None:
        display = get_decision_display(two_score_result())

        self.assertEqual(display["final_level"], "High suspicion")
        self.assertEqual(display["conclusion"], "Partially suspicious")
        self.assertEqual(display["confidence_level"], "Low")
        self.assertTrue(display["has_score_conflict"])
        self.assertEqual(display["risk_vote"], "Reached suspicious benchmark")
        self.assertEqual(display["judgement_vote"], "Below suspicious benchmark")
        self.assertEqual(display["benchmark"], "79 / 100")
        self.assertEqual(display["agreement_margin"], "1")
        self.assertEqual(
            display["threshold_ranges"],
            [
                ("Low suspicion", "0 to below 62"),
                ("Medium suspicion", "62 to below 79"),
                ("High suspicion", "79 to below 100"),
                ("Dangerous", "100 to 100"),
            ],
        )
        self.assertEqual(display["policy"], "phase3-decision-policy-v1 (provisional)")

    def test_score_evidence_keeps_risk_judgement_trust_and_confidence_distinct(self) -> None:
        result = two_score_result()
        evidence = get_score_evidence_display(result)
        decision = get_decision_display(result)

        self.assertEqual(evidence["risk_score"], "90 / 100")
        self.assertEqual(evidence["risk_label"], "url.vet risk score")
        self.assertEqual(evidence["judgement_score"], "20 / 100")
        self.assertEqual(evidence["trust_score"], "25 / 100")
        self.assertEqual(evidence["risk_level"], "High suspicion")
        self.assertEqual(evidence["judgement_level"], "Low suspicion")
        self.assertEqual(decision["confidence_level"], "Low")
        self.assertNotEqual(evidence["trust_score"], decision["confidence_level"])
        self.assertEqual(evidence["url_vet_reasons"], ["url.vet found a destination risk signal."])
        self.assertEqual(
            evidence["judgement_reasons"],
            ["The local model found fewer lexical signals."],
        )

    def test_incomplete_score_evidence_preserves_available_check_details(self) -> None:
        result = {
            "analysis": None,
            "decision": {
                "conclusion": "Incomplete",
                "confidence_level": "Unavailable",
                "confidence_reason": "url.vet risk score is unavailable.",
                "risk_score_level": None,
                "judgement_score_level": "Medium suspicion",
                "risk_vote_suspicious": None,
                "judgement_vote_suspicious": False,
            },
            "checks": [
                {
                    "check_id": "url_vet",
                    "status": "incomplete",
                    "details": {"trust_score": 40.0, "verdict": "Not available"},
                },
                {
                    "check_id": "local_judgement",
                    "status": "passed",
                    "details": {
                        "judgement_score": 65.5,
                        "reasons": ["Local lexical evidence remained available."],
                    },
                },
            ],
        }

        evidence = get_score_evidence_display(result)
        self.assertEqual(evidence["risk_score"], "Not available")
        self.assertEqual(evidence["risk_label"], "url.vet risk signal")
        self.assertIn("Partial signal", evidence["risk_context"])
        self.assertEqual(evidence["judgement_score"], "65.5 / 100")
        self.assertEqual(evidence["trust_score"], "40 / 100")
        self.assertEqual(evidence["url_vet_status"], "incomplete")
        self.assertEqual(
            evidence["judgement_reasons"],
            ["Local lexical evidence remained available."],
        )

    def test_partial_local_assessment_has_warning_presentation(self) -> None:
        display = get_result_presentation(
            {
                "analysis_status": "Partial",
                "assessment_outcome": "Review required",
                "analysis": {
                    "model_name": "LogisticRegression",
                    "score": 58.99,
                    "judgement_score": 58.99,
                },
                "decision": {
                    "conclusion": "Partially assessed",
                    "suspicion_level": "Low suspicion",
                    "confidence_level": "Low",
                },
            }
        )

        self.assertEqual(display["title"], "Partial URL assessment")
        self.assertEqual(display["tone"], "warning")
        self.assertIn("url.vet did not complete", display["summary"])

    def test_not_applicable_decision_has_explicit_display_state(self) -> None:
        display = get_decision_display(
            {
                "decision": {
                    "conclusion": "Not applicable",
                    "confidence_level": "Unavailable",
                }
            }
        )

        self.assertEqual(display["final_level"], "Not applicable")
        self.assertEqual(display["confidence_level"], "Not applicable")

    def test_qr_content_display_identifies_wifi_payload(self) -> None:
        display = get_qr_content_display(
            {
                "content_type": "text",
                "decoded_text": "WIFI:T:WPA;S:Howie's Network;P:123456;;",
            }
        )

        self.assertEqual(display["label"], "WiFi network QR")
        self.assertIn("local", display["summary"])
        self.assertIn(("SSID", "Howie's Network"), display["fields"])
        self.assertIn(("Security", "WPA"), display["fields"])
        self.assertIn(("Password", "123456"), display["fields"])
        self.assert_non_url_guidance(display)

    def test_qr_content_display_identifies_vcard_payload(self) -> None:
        display = get_qr_content_display(
            {
                "content_type": "text",
                "decoded_text": (
                    "BEGIN:VCARD\n"
                    "VERSION:3.0\n"
                    "FN:Alex Chen\n"
                    "ORG:Example Lab\n"
                    "TEL;TYPE=CELL:0400000000\n"
                    "EMAIL:alex@example.test\n"
                    "URL:https://example.test\n"
                    "END:VCARD"
                ),
            }
        )

        self.assertEqual(display["label"], "Contact card QR")
        self.assertIn(("Name", "Alex Chen"), display["fields"])
        self.assertIn(("Organisation", "Example Lab"), display["fields"])
        self.assertIn(("Phone", "0400000000"), display["fields"])
        self.assertIn(("Email", "alex@example.test"), display["fields"])
        self.assertIn(("Website", "https://example.test"), display["fields"])
        self.assert_non_url_guidance(display)

    def test_qr_content_display_identifies_plain_text_payload(self) -> None:
        display = get_qr_content_display(
            {"content_type": "text", "decoded_text": "Hello World!"}
        )

        self.assertEqual(display["label"], "Plain text QR")
        self.assertIn(("Preview", "Hello World!"), display["fields"])
        self.assert_non_url_guidance(display)

    def test_qr_content_display_identifies_unsupported_uri_and_requests_review(self) -> None:
        display = get_qr_content_display(
            {
                "content_type": "text",
                "decoded_text": "ftp://example.com/file",
            }
        )

        self.assertEqual(display["label"], "Unsupported URI QR")
        self.assertIn(("Scheme", "ftp"), display["fields"])
        self.assert_non_url_guidance(display)

    def test_qr_content_display_handles_malformed_web_url_without_crashing(self) -> None:
        display = get_qr_content_display(
            {
                "content_type": "url",
                "decoded_text": "https://[bad-ip]/",
            }
        )

        self.assertEqual(display["label"], "Malformed web URL QR")
        self.assert_non_url_guidance(display)

    def test_qr_content_display_marks_local_payment_payload_for_manual_review(self) -> None:
        display = get_qr_content_display(
            {
                "content_type": "payment",
                "decoded_text": "QRSHIELD-PAY:v1;merchant_id=uni-cafe;",
            }
        )

        self.assertEqual(display["label"], "Payment QR")
        self.assert_non_url_guidance(display)

    def test_qr_content_display_identifies_alipay_payment_link(self) -> None:
        display = get_qr_content_display(
            {
                "content_type": "url",
                "hostname": "qr.alipay.com",
                "decoded_text": "HTTPS://QR.ALIPAY.COM/FKX00053VYX4EQZDGVLKD8",
            }
        )

        self.assertEqual(display["label"], "Payment link QR")
        self.assertIn(("Provider", "Alipay"), display["fields"])
        self.assertIn(("Hostname", "qr.alipay.com"), display["fields"])

    def test_qr_content_display_identifies_supported_web_url(self) -> None:
        display = get_qr_content_display(
            {
                "content_type": "url",
                "hostname": "example.com",
                "decoded_text": "https://example.com",
            }
        )

        self.assertEqual(display["label"], "Web URL QR")
        self.assertIn(("Hostname", "example.com"), display["fields"])
        self.assertFalse(display["is_non_url"])
        self.assertIsNone(display["guidance"])

    def test_result_presentation_never_calls_low_risk_safe(self) -> None:
        display = get_result_presentation(
            {
                "assessment_outcome": "Risk assessed",
                "analysis_status": "Complete",
                "analysis": {"level": "Low"},
            }
        )
        self.assertEqual(display["title"], "No major risk signals found")
        self.assertIn("not a safety guarantee", display["summary"])

    def test_result_presentation_uses_conservative_decision_over_old_low_level(self) -> None:
        display = get_result_presentation(
            {
                "assessment_outcome": "Review required",
                "analysis_status": "Complete",
                "analysis": {"level": "Low"},
                "decision": {
                    "conclusion": "Suspicious",
                    "suspicion_level": "Dangerous",
                },
            }
        )

        self.assertEqual(display["tone"], "error")
        self.assertEqual(display["title"], "Dangerous URL signals detected")
        self.assertNotIn("No major", display["title"])

    def test_incomplete_result_has_a_recovery_action(self) -> None:
        display = get_result_presentation(
            {"assessment_outcome": "Incomplete", "analysis_status": "Incomplete"}
        )
        self.assertEqual(display["title"], "Unable to complete all checks")
        self.assertIn("clearer image", display["action"])

    def test_student_ui_contains_no_chinese_characters(self) -> None:
        root = Path(__file__).resolve().parents[1]
        ui_text = "\n".join(
            (root / relative).read_text(encoding="utf-8")
            for relative in ("app/ui/streamlit_app.py", "app/ui/presentation.py")
        )
        self.assertIsNone(re.search(r"[\u3400-\u9fff]", ui_text))

    def test_student_ui_explains_url_vet_inspection_boundary(self) -> None:
        root = Path(__file__).resolve().parents[1]
        ui_text = (root / "app/ui/streamlit_app.py").read_text(encoding="utf-8")
        self.assertIn("processed locally and is not retained", ui_text)
        self.assertIn("local url.vet service to inspect the destination", ui_text)
        self.assertIn("never opened automatically", ui_text)
        self.assertNotIn("Your image is analysed locally and is not retained.", ui_text)

    def test_student_ui_separates_confidence_from_url_vet_trust_and_keeps_user_control(self) -> None:
        root = Path(__file__).resolve().parents[1]
        ui_text = (root / "app/ui/streamlit_app.py").read_text(encoding="utf-8")
        self.assertIn("QR Shield confidence", ui_text)
        self.assertIn("url.vet trust evidence", ui_text)
        self.assertIn("this is not QR Shield confidence", ui_text)
        self.assertIn("You make the final decision", ui_text)
        self.assertIn("does not automatically open, block, redirect, connect, or pay", ui_text)

    def test_student_ui_renders_non_url_guidance(self) -> None:
        root = Path(__file__).resolve().parents[1]
        ui_text = (root / "app/ui/streamlit_app.py").read_text(encoding="utf-8")
        self.assertIn('guidance = content_display.get("guidance")', ui_text)
        self.assertIn('if guidance:', ui_text)
        self.assertIn('st.info(str(guidance))', ui_text)
