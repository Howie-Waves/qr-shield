import unittest
from pathlib import Path

import cv2
import socket
import urllib.request
import webbrowser
from fastapi.testclient import TestClient
from unittest.mock import patch

from app.main import app
from app.services.model_service import ModelUnavailableError
from app.services.qr_decoder import MAX_IMAGE_SIZE
from app.services.risk_decision import DecisionPolicyUnavailableError


def make_qr_image(payload: str, extension: str = ".png") -> bytes:
    image = cv2.QRCodeEncoder_create().encode(payload)
    image = cv2.resize(image, None, fx=10, fy=10, interpolation=cv2.INTER_NEAREST)
    ok, encoded = cv2.imencode(extension, image)
    if not ok:
        raise RuntimeError("Could not encode test QR image.")
    return encoded.tobytes()


def url_vet_result(
    score: float = 5.0,
    level: str = "Low",
    verdict: str = "Safe",
) -> tuple[dict, dict]:
    return (
        {
            "check_id": "url_vet",
            "status": "passed",
            "summary": "url.vet URL risk analysis completed.",
            "reason_codes": [f"URL_VET_VERDICT_{verdict.upper()}"],
            "details": {"version": "urlvet-test-v1"},
        },
        {
            "score": score,
            "level": level,
            "reasons": ["Long-standing domain history."],
            "model_name": "url.vet",
            "model_version": "urlvet-test-v1",
            "trust_score": 100.0,
            "verdict": verdict,
        },
    )


def url_vet_incomplete_result() -> tuple[dict, None]:
    return (
        {
            "check_id": "url_vet",
            "status": "incomplete",
            "summary": "url.vet is unavailable.",
            "reason_codes": ["URL_VET_UNAVAILABLE"],
            "details": {"version": "urlvet-test-v1"},
        },
        None,
    )


def local_judgement_result(score: float = 12.5) -> dict:
    return {
        "score": score,
        "level": "Low",
        "is_phishing": False,
        "reasons": ["No configured high-risk lexical signals were found."],
        "model_name": "LogisticRegression",
        "model_version": "url-risk-lr-test-v1",
        "threshold": 0.5,
        "risk_level_thresholds": {"low_max_exclusive": 40, "medium_max_exclusive": 70},
    }


class E1US1APITests(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        cls.client = TestClient(app)

    def test_valid_upload_decodes_without_opening_destination(self) -> None:
        with patch("app.main.analyze_url", return_value=url_vet_result()), patch(
            "app.main.predict_url_risk", return_value=local_judgement_result()
        ):
            response = self.client.post(
                "/api/v1/analyze",
                files={"file": ("code.png", make_qr_image("https://example.com"), "image/png")},
            )
        self.assertEqual(response.status_code, 200)
        body = response.json()
        self.assertEqual(body["decoded_text"], "https://example.com")
        self.assertEqual(body["content_type"], "url")
        self.assertEqual(body["hostname"], "example.com")
        self.assertEqual(body["block_inspection"]["id"], "block_inspection")
        self.assertEqual(len(body["block_inspection"]["evidence"]["regions"]), 5)
        self.assertGreaterEqual(body["analysis"]["score"], 0)
        self.assertLessEqual(body["analysis"]["score"], 100)
        self.assertEqual(body["analysis"]["risk_score"], body["analysis"]["score"])
        self.assertEqual(body["analysis"]["judgement_score"], 12.5)
        self.assertEqual(body["analysis"]["judgement_model_name"], "LogisticRegression")
        self.assertEqual(body["analysis"]["judgement_model_version"], "url-risk-lr-test-v1")
        self.assertEqual(body["decision"]["conclusion"], "Not suspicious")
        self.assertEqual(body["decision"]["suspicion_level"], "Low suspicion")
        self.assertEqual(body["decision"]["confidence_level"], "Medium")
        self.assertEqual(body["decision"]["policy_version"], "phase3-decision-policy-v1")
        self.assertIn(body["analysis"]["level"], {"Low", "Medium", "High"})
        self.assertGreaterEqual(len(body["analysis"]["reasons"]), 1)
        self.assertLessEqual(len(body["analysis"]["reasons"]), 3)
        self.assertIn("not opened", body["message"])
        self.assertEqual(body["assessment_outcome"], "Risk assessed")
        self.assertEqual(
            {item["check_id"] for item in body["checks"]},
            {"block_inspection", "local_denylist", "local_judgement", "payment", "url_vet"},
        )
        self.assertIn("url_vet", body["source_versions"])
        self.assertEqual(body["source_versions"]["local_judgement"], "url-risk-lr-test-v1")
        self.assertEqual(body["source_versions"]["decision_policy"], "phase3-decision-policy-v1")
        self.assertIn("local_denylist", body["source_versions"])

    def test_same_url_has_a_deterministic_score_and_level(self) -> None:
        image = make_qr_image("https://example.com")
        with patch("app.main.analyze_url", return_value=url_vet_result()), patch(
            "app.main.predict_url_risk", return_value=local_judgement_result()
        ):
            first = self.client.post("/api/v1/analyze", files={"file": ("a.png", image, "image/png")}).json()
            second = self.client.post("/api/v1/analyze", files={"file": ("b.png", image, "image/png")}).json()
        self.assertEqual(first["analysis"]["score"], second["analysis"]["score"])
        self.assertEqual(first["analysis"]["level"], second["analysis"]["level"])
        self.assertEqual(first["analysis"]["judgement_score"], second["analysis"]["judgement_score"])

    def test_supported_url_returns_url_vet_risk_and_local_judgement(self) -> None:
        image = make_qr_image("https://example.com")
        url_vet_check = {
            "check_id": "url_vet",
            "status": "passed",
            "summary": "url.vet URL risk analysis completed.",
            "reason_codes": ["URL_VET_VERDICT_SAFE"],
            "details": {"version": "urlvet-test-v1"},
        }
        url_vet_analysis = {
            "score": 5.0,
            "level": "Low",
            "reasons": ["Long-standing domain history."],
            "model_name": "url.vet",
            "model_version": "urlvet-test-v1",
            "trust_score": 100.0,
            "verdict": "Safe",
        }
        with (
            patch("app.main.analyze_url", create=True, return_value=(url_vet_check, url_vet_analysis)) as analyze_url,
            patch("app.main.predict_url_risk", return_value=local_judgement_result(21.75)) as local_model,
        ):
            response = self.client.post(
                "/api/v1/analyze",
                files={"file": ("code.png", image, "image/png")},
            )

        self.assertEqual(response.status_code, 200)
        body = response.json()
        analyze_url.assert_called_once_with("https://example.com")
        local_model.assert_called_once_with("https://example.com")
        self.assertEqual(body["analysis"]["model_name"], "url.vet")
        self.assertEqual(body["analysis"]["risk_score"], 5.0)
        self.assertEqual(body["analysis"]["judgement_score"], 21.75)
        self.assertEqual(body["analysis"]["trust_score"], 100.0)
        self.assertEqual(body["analysis"]["verdict"], "Safe")
        self.assertIn("url_vet", {item["check_id"] for item in body["checks"]})
        judgement_check = next(
            item for item in body["checks"] if item["check_id"] == "local_judgement"
        )
        self.assertEqual(judgement_check["status"], "passed")
        self.assertEqual(judgement_check["details"]["judgement_score"], 21.75)
        self.assertEqual(body["source_versions"]["url_vet"], "urlvet-test-v1")
        self.assertEqual(body["source_versions"]["local_judgement"], "url-risk-lr-test-v1")

    def test_score_conflict_requires_review_and_keeps_the_higher_level(self) -> None:
        image = make_qr_image("https://example.com")
        with patch("app.main.analyze_url", return_value=url_vet_result(score=90, level="High")), patch(
            "app.main.predict_url_risk", return_value=local_judgement_result(20)
        ):
            response = self.client.post(
                "/api/v1/analyze", files={"file": ("code.png", image, "image/png")}
            )

        body = response.json()
        self.assertEqual(body["decision"]["conclusion"], "Partially suspicious")
        self.assertEqual(body["decision"]["suspicion_level"], "High suspicion")
        self.assertEqual(body["decision"]["confidence_level"], "Low")
        self.assertIn("disagree", body["decision"]["confidence_reason"])
        self.assertEqual(body["assessment_outcome"], "Review required")

    def test_malicious_verdict_with_low_scores_is_dangerous_and_requires_review(self) -> None:
        image = make_qr_image("https://example.com")
        with patch(
            "app.main.analyze_url",
            return_value=url_vet_result(score=5, level="Low", verdict="Malicious"),
        ), patch("app.main.predict_url_risk", return_value=local_judgement_result(5)):
            response = self.client.post(
                "/api/v1/analyze", files={"file": ("code.png", image, "image/png")}
            )

        body = response.json()
        self.assertEqual(body["decision"]["conclusion"], "Suspicious")
        self.assertEqual(body["decision"]["suspicion_level"], "Dangerous")
        self.assertEqual(body["decision"]["confidence_level"], "Low")
        self.assertEqual(body["assessment_outcome"], "Review required")

    def test_unavailable_decision_policy_returns_incomplete_not_a_guessed_result(self) -> None:
        image = make_qr_image("https://example.com")
        with patch("app.main.analyze_url", return_value=url_vet_result()), patch(
            "app.main.predict_url_risk", return_value=local_judgement_result()
        ), patch(
            "app.main.decide_url_risk",
            side_effect=DecisionPolicyUnavailableError("missing policy"),
        ):
            response = self.client.post(
                "/api/v1/analyze", files={"file": ("code.png", image, "image/png")}
            )

        body = response.json()
        self.assertEqual(body["decision"]["conclusion"], "Incomplete")
        self.assertEqual(body["decision"]["confidence_level"], "Unavailable")
        self.assertEqual(body["assessment_outcome"], "Incomplete")
        self.assertIn("decision_policy", body["failed_check_ids"])

    def test_unavailable_url_vet_returns_local_partial_result(self) -> None:
        image = make_qr_image("https://example.com")
        with patch("app.main.analyze_url", return_value=url_vet_incomplete_result()), patch(
            "app.main.predict_url_risk", return_value=local_judgement_result()
        ) as local_model:
            response = self.client.post(
                "/api/v1/analyze", files={"file": ("code.png", image, "image/png")}
            )
        self.assertEqual(response.status_code, 200)
        body = response.json()
        self.assertIsNotNone(body["analysis"])
        self.assertEqual(body["analysis_status"], "Partial")
        self.assertEqual(body["failed_check_ids"], ["url_vet"])
        self.assertEqual(body["assessment_outcome"], "Review required")
        local_model.assert_called_once_with("https://example.com")
        self.assertIsNone(body["analysis"]["risk_score"])
        self.assertEqual(body["analysis"]["judgement_score"], 12.5)
        self.assertEqual(body["decision"]["conclusion"], "Partially assessed")
        self.assertEqual(body["decision"]["confidence_level"], "Low")
        self.assertEqual(body["source_versions"]["local_judgement"], "url-risk-lr-test-v1")
        url_vet_check = next(item for item in body["checks"] if item["check_id"] == "url_vet")
        self.assertEqual(url_vet_check["status"], "incomplete")

    def test_partial_url_vet_score_is_kept_and_marked_for_review(self) -> None:
        image = make_qr_image("https://example.com")
        partial_check = {
            "check_id": "url_vet",
            "status": "warning",
            "summary": "url.vet returned partial analysis; available risk evidence is shown.",
            "reason_codes": ["URL_VET_PARTIAL"],
            "details": {
                "version": "urlvet-test-v1",
                "risk_score": 30.0,
                "risk_level": "Low",
                "trust_score": 100.0,
                "verdict": "Safe",
                "reasons": ["Sensitive security keywords found in URL: login"],
            },
        }
        partial_analysis = {
            "score": 30.0,
            "risk_score": 30.0,
            "level": "Low",
            "reasons": ["Sensitive security keywords found in URL: login"],
            "model_name": "url.vet",
            "model_version": "urlvet-test-v1",
            "trust_score": 100.0,
            "verdict": "Safe",
            "url_vet_partial": True,
        }
        with patch(
            "app.main.analyze_url",
            return_value=(partial_check, partial_analysis),
        ), patch("app.main.predict_url_risk", return_value=local_judgement_result(58.99)):
            body = self.client.post(
                "/api/v1/analyze",
                files={"file": ("code.png", image, "image/png")},
            ).json()

        self.assertEqual(body["analysis_status"], "Partial")
        self.assertEqual(body["assessment_outcome"], "Review required")
        self.assertEqual(body["analysis"]["risk_score"], 30.0)
        self.assertEqual(body["analysis"]["judgement_score"], 58.99)
        self.assertTrue(body["analysis"]["url_vet_partial"])
        self.assertEqual(body["decision"]["conclusion"], "Partially assessed")
        self.assertEqual(body["decision"]["confidence_level"], "Low")
        self.assertIn("partial evidence", body["decision"]["confidence_reason"])

    def test_other_mandatory_check_failure_stays_incomplete(self) -> None:
        image = make_qr_image("https://example.com")
        partial_check = {
            "check_id": "url_vet",
            "status": "warning",
            "summary": "Partial URL evidence.",
            "reason_codes": ["URL_VET_PARTIAL"],
            "details": {"version": "urlvet-test-v1", "risk_score": 30.0},
        }
        partial_analysis = {
            "score": 30.0,
            "risk_score": 30.0,
            "level": "Low",
            "reasons": [],
            "model_name": "url.vet",
            "model_version": "urlvet-test-v1",
            "trust_score": 100.0,
            "verdict": "Safe",
            "url_vet_partial": True,
        }
        with patch(
            "app.main.check_denylist",
            return_value={
                "check_id": "local_denylist",
                "status": "incomplete",
                "summary": "Denylist unavailable.",
                "reason_codes": ["DENYLIST_UNAVAILABLE"],
                "details": {},
            },
        ), patch("app.main.analyze_url", return_value=(partial_check, partial_analysis)):
            body = self.client.post(
                "/api/v1/analyze",
                files={"file": ("code.png", image, "image/png")},
            ).json()

        self.assertEqual(body["analysis_status"], "Incomplete")
        self.assertEqual(body["assessment_outcome"], "Incomplete")
        self.assertIn("local_denylist", body["failed_check_ids"])

    def test_unavailable_local_judgement_returns_url_vet_partial_result(self) -> None:
        image = make_qr_image("https://example.com")
        with patch("app.main.analyze_url", return_value=url_vet_result()), patch(
            "app.main.predict_url_risk", side_effect=ModelUnavailableError("missing model")
        ):
            response = self.client.post(
                "/api/v1/analyze", files={"file": ("code.png", image, "image/png")}
            )

        body = response.json()
        self.assertEqual(body["analysis_status"], "Partial")
        self.assertEqual(body["assessment_outcome"], "Review required")
        self.assertEqual(body["failed_check_ids"], ["local_judgement"])
        self.assertEqual(body["analysis"]["risk_score"], 5.0)
        self.assertIsNone(body["analysis"]["judgement_score"])
        self.assertEqual(body["decision"]["conclusion"], "Partially assessed")
        self.assertEqual(body["decision"]["confidence_level"], "Low")
        judgement_check = next(
            item for item in body["checks"] if item["check_id"] == "local_judgement"
        )
        self.assertEqual(judgement_check["reason_codes"], ["LOCAL_JUDGEMENT_UNAVAILABLE"])

    def test_e1_us2_risk_fixtures_keep_a_local_score_when_url_vet_is_unavailable(self) -> None:
        fixture_scores = {
            "low.png": 1.93,
            "medium.png": 58.99,
            "high.png": 100.0,
        }

        def local_score(url: str) -> dict:
            if "monash.edu" in url:
                score = fixture_scores["low.png"]
            elif "a.b.c.example.com" in url:
                score = fixture_scores["medium.png"]
            else:
                score = fixture_scores["high.png"]
            return local_judgement_result(score)

        fixture_root = (
            Path(__file__).resolve().parents[1]
            / "data"
            / "test_images"
            / "e1_us2_risk"
        )
        with patch("app.main.analyze_url", return_value=url_vet_incomplete_result()), patch(
            "app.main.predict_url_risk", side_effect=local_score
        ):
            for fixture_name, expected_score in fixture_scores.items():
                with self.subTest(fixture=fixture_name):
                    image_path = fixture_root / fixture_name
                    body = self.client.post(
                        "/api/v1/analyze",
                        files={
                            "file": (
                                image_path.name,
                                image_path.read_bytes(),
                                "image/png",
                            )
                        },
                    ).json()

                    self.assertEqual(body["analysis_status"], "Partial")
                    self.assertEqual(body["assessment_outcome"], "Review required")
                    self.assertIsNotNone(body["analysis"])
                    self.assertIsNone(body["analysis"]["risk_score"])
                    self.assertEqual(body["analysis"]["judgement_score"], expected_score)
                    self.assertEqual(body["decision"]["confidence_level"], "Low")
                    self.assertIn(
                        body["decision"]["conclusion"],
                        {"Partially assessed", "Partially suspicious"},
                    )

    def test_unavailable_evidence_source_returns_incomplete(self) -> None:
        image = make_qr_image("https://example.com")
        with patch(
            "app.main.check_denylist",
            return_value={
                "check_id": "local_denylist",
                "status": "incomplete",
                "summary": "Source unavailable.",
                "reason_codes": ["DENYLIST_UNAVAILABLE"],
                "details": {},
            },
        ), patch("app.main.analyze_url", return_value=url_vet_result()):
            response = self.client.post(
                "/api/v1/analyze", files={"file": ("code.png", image, "image/png")}
            )
        body = response.json()
        self.assertEqual(body["analysis_status"], "Incomplete")
        self.assertIn("local_denylist", body["failed_check_ids"])

    def test_conflicting_evidence_requires_review(self) -> None:
        image = make_qr_image("https://example.com")
        with patch(
            "app.main.check_denylist",
            return_value={
                "check_id": "local_denylist",
                "status": "failed",
                "summary": "Listed hostname.",
                "reason_codes": ["DENYLIST_MATCH"],
                "details": {"version": "test-v1"},
            },
        ), patch("app.main.analyze_url", return_value=url_vet_result()):
            response = self.client.post(
                "/api/v1/analyze", files={"file": ("code.png", image, "image/png")}
            )
        body = response.json()
        self.assertEqual(body["assessment_outcome"], "Review required")
        self.assertNotEqual(body["assessment_outcome"], "Risk assessed")

    def test_plain_text_is_explicitly_not_scored(self) -> None:
        with patch("app.main.analyze_url") as analyze_url, patch(
            "app.main.predict_url_risk"
        ) as local_model:
            response = self.client.post(
                "/api/v1/analyze",
                files={"file": ("text.png", make_qr_image("plain text"), "image/png")},
            )
        body = response.json()
        analyze_url.assert_not_called()
        local_model.assert_not_called()
        self.assertEqual(body["analysis_status"], "Not scored")
        self.assertIsNone(body["analysis"])
        self.assertEqual(body["decision"]["conclusion"], "Not applicable")
        self.assertEqual(body["decision"]["suspicion_level"], "Not applicable")
        self.assertEqual(body["decision"]["confidence_level"], "Not applicable")
        self.assertIn("URL risk scoring was not performed", body["message"])
        url_vet_check = next(item for item in body["checks"] if item["check_id"] == "url_vet")
        self.assertEqual(url_vet_check["status"], "not_applicable")

    def test_unsupported_uri_scheme_is_not_sent_to_url_vet(self) -> None:
        with patch("app.main.analyze_url") as analyze_url, patch(
            "app.main.predict_url_risk"
        ) as local_model:
            response = self.client.post(
                "/api/v1/analyze",
                files={"file": ("ftp.png", make_qr_image("ftp://example.com/file"), "image/png")},
            )
        body = response.json()
        analyze_url.assert_not_called()
        local_model.assert_not_called()
        self.assertEqual(body["content_type"], "text")
        self.assertEqual(body["analysis_status"], "Not scored")
        self.assertIsNone(body["analysis"])
        self.assertEqual(body["decision"]["conclusion"], "Not applicable")
        self.assertEqual(body["decision"]["suspicion_level"], "Not applicable")
        self.assertEqual(body["decision"]["confidence_level"], "Not applicable")
        url_vet_check = next(item for item in body["checks"] if item["check_id"] == "url_vet")
        self.assertEqual(url_vet_check["status"], "not_applicable")
        self.assertIn("unsupported URI scheme", url_vet_check["summary"])

    def test_structured_non_web_payload_is_not_sent_to_url_vet(self) -> None:
        payload = "WIFI:S:Monash;T:WPA;P:secret;;"
        with patch("app.main.analyze_url") as analyze_url, patch(
            "app.main.predict_url_risk"
        ) as local_model:
            response = self.client.post(
                "/api/v1/analyze",
                files={"file": ("wifi.png", make_qr_image(payload), "image/png")},
            )
        body = response.json()
        analyze_url.assert_not_called()
        local_model.assert_not_called()
        self.assertEqual(body["content_type"], "text")
        self.assertEqual(body["analysis_status"], "Not scored")
        self.assertIsNone(body["analysis"])
        self.assertEqual(body["decision"]["conclusion"], "Not applicable")
        self.assertEqual(body["decision"]["suspicion_level"], "Not applicable")
        self.assertEqual(body["decision"]["confidence_level"], "Not applicable")
        url_vet_check = next(item for item in body["checks"] if item["check_id"] == "url_vet")
        self.assertEqual(url_vet_check["status"], "not_applicable")
        self.assertIn("structured non-web", url_vet_check["summary"].casefold())

    def test_malformed_url_is_not_sent_to_model(self) -> None:
        with patch("app.main.analyze_url") as analyze_url, patch(
            "app.main.predict_url_risk"
        ) as local_model:
            response = self.client.post(
                "/api/v1/analyze",
                files={"file": ("bad.png", make_qr_image("https://[bad-ip]/"), "image/png")},
            )
        body = response.json()
        analyze_url.assert_not_called()
        local_model.assert_not_called()
        self.assertEqual(body["analysis_status"], "Not scored")
        self.assertIsNone(body["analysis"])
        self.assertIn("URL risk scoring was not performed", body["message"])
        url_vet_check = next(item for item in body["checks"] if item["check_id"] == "url_vet")
        self.assertEqual(url_vet_check["status"], "not_applicable")
        self.assertIn("malformed", url_vet_check["summary"].casefold())
        self.assertNotIn("url_model", {item["check_id"] for item in body["checks"]})

    def test_full_analysis_never_accesses_the_decoded_destination(self) -> None:
        with (
            patch.object(urllib.request, "urlopen") as urlopen,
            patch.object(socket, "create_connection") as create_connection,
            patch.object(socket, "getaddrinfo") as getaddrinfo,
            patch.object(webbrowser, "open") as browser_open,
            patch("app.main.analyze_url", return_value=url_vet_result()),
        ):
            response = self.client.post(
                "/api/v1/analyze",
                files={"file": ("code.png", make_qr_image("https://example.com"), "image/png")},
            )
        self.assertEqual(response.status_code, 200)
        urlopen.assert_not_called()
        create_connection.assert_not_called()
        getaddrinfo.assert_not_called()
        browser_open.assert_not_called()

    def test_payment_qr_is_verified_without_url_scoring(self) -> None:
        payload = "QRSHIELD-PAY:v1;merchant_id=uni-cafe;payee_id=payee-4821;amount=12.50;currency=AUD"
        with patch("app.main.analyze_url") as analyze_url, patch(
            "app.main.predict_url_risk"
        ) as local_model:
            response = self.client.post(
                "/api/v1/analyze", files={"file": ("payment.png", make_qr_image(payload), "image/png")}
            )
        body = response.json()
        analyze_url.assert_not_called()
        local_model.assert_not_called()
        self.assertEqual(body["content_type"], "payment")
        self.assertEqual(body["payment"]["status"], "passed")
        self.assertIsNone(body["analysis"])
        url_vet_check = next(item for item in body["checks"] if item["check_id"] == "url_vet")
        self.assertEqual(url_vet_check["status"], "not_applicable")
        self.assertIn("payment", url_vet_check["summary"].casefold())

    def test_unknown_payment_reference_is_unverifiable(self) -> None:
        payload = "QRSHIELD-PAY:v1;merchant_id=unknown;payee_id=payee-9999;amount=10.00;currency=AUD"
        response = self.client.post(
            "/api/v1/analyze", files={"file": ("payment.png", make_qr_image(payload), "image/png")}
        )
        payment = response.json()["payment"]
        self.assertEqual(payment["status"], "unverifiable")
        self.assertIn("Confirm the payee and amount", payment["summary"])

    def test_invalid_uploads_return_recoverable_errors(self) -> None:
        cases = (
            ("empty.png", b"", "image/png", 400),
            ("broken.png", b"not an image", "image/png", 400),
            ("code.gif", b"not an image", "image/gif", 400),
            ("large.png", b"x" * (MAX_IMAGE_SIZE + 1), "image/png", 413),
        )
        for name, content, mime_type, expected in cases:
            with self.subTest(name=name):
                response = self.client.post(
                    "/api/v1/analyze", files={"file": (name, content, mime_type)}
                )
                self.assertEqual(response.status_code, expected)

    def test_explicit_review_request_returns_a_case_id(self) -> None:
        import os
        import tempfile

        with tempfile.TemporaryDirectory() as directory, patch.dict(
            os.environ, {"QR_REVIEW_DB_PATH": f"{directory}/review.db"}
        ):
            response = self.client.post(
                "/api/v1/review-cases",
                json={
                    "payload": "https://private.example/path",
                    "hostname": "private.example",
                    "assessment_outcome": "Review required",
                    "model_version": "test-v1",
                    "reason_codes": ["TEST"],
                    "consent": True,
                },
            )
        self.assertEqual(response.status_code, 200)
        self.assertTrue(response.json()["case_id"])

    def test_review_request_without_consent_is_rejected(self) -> None:
        response = self.client.post(
            "/api/v1/review-cases",
            json={
                "payload": "https://private.example/path",
                "assessment_outcome": "Review required",
                "consent": False,
            },
        )
        self.assertEqual(response.status_code, 400)

    def test_ordinary_analysis_creates_no_review_record(self) -> None:
        import os
        import tempfile

        with tempfile.TemporaryDirectory() as directory, patch.dict(
            os.environ, {"QR_REVIEW_DB_PATH": f"{directory}/review.db"}
        ), patch("app.main.analyze_url", return_value=url_vet_result()):
            response = self.client.post(
                "/api/v1/analyze",
                files={"file": ("code.png", make_qr_image("https://example.com"), "image/png")},
            )
            self.assertEqual(response.status_code, 200)
            self.assertFalse(Path(directory, "review.db").exists())

    def test_second_upload_is_independent_after_failed_upload(self) -> None:
        failed = self.client.post(
            "/api/v1/analyze", files={"file": ("broken.png", b"broken", "image/png")}
        )
        success = self.client.post(
            "/api/v1/analyze",
            files={"file": ("next.png", make_qr_image("plain text"), "image/png")},
        )
        self.assertEqual(failed.status_code, 400)
        self.assertEqual(success.status_code, 200)
        self.assertEqual(success.json()["decoded_text"], "plain text")
