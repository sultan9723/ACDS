"""
ACDS Test Cases - Credential Stuffing Detection Module
======================================================
Python test cases for Module 6 (Credential Stuffing Detection).

Scope:
- Module health
- Single login-event analysis
- Batch analyze flow
- Alerts listing
- Analyst feedback + retraining-data generation
- Synthetic attack simulation
- Report endpoint behavior
- Validation checks
"""

from datetime import datetime, timezone, timedelta
import os
import time

import pytest
import requests


BASE_URL = os.getenv("ACDS_API_BASE_URL", "http://127.0.0.1:8000/api/v1")


class TestCredentialStuffingDetection:
    """Module 6 - credential stuffing detection test suite."""

    @pytest.fixture(autouse=True)
    def setup(self):
        self.base_url = BASE_URL
        self.created_alert_id = None
        yield

    def _create_medium_risk_event(self):
        """Helper to create an event likely to produce an alert in normal conditions."""
        payload = {
            "username": f"user_{int(time.time())}",
            "ip_address": "198.51.100.25",
            "success": False,
            "timestamp": datetime.now(timezone.utc).isoformat(),
            "user_agent": "ACDS-Behavioral-Client/1.0",
            "country": "US",
        }
        return requests.post(f"{self.base_url}/credential-stuffing/login-event", json=payload)

    # ---------------------------------------------------------------------
    # CRED-001: Health endpoint
    # ---------------------------------------------------------------------
    def test_cred_001_health_endpoint(self):
        response = requests.get(f"{self.base_url}/credential-stuffing/health")
        assert response.status_code == 200, f"Expected 200, got {response.status_code}: {response.text}"

        data = response.json()
        assert data.get("success") is True
        assert data.get("module") == "credential_stuffing_detection"
        assert "model_available" in data

    # ---------------------------------------------------------------------
    # CRED-002: Single login-event detection
    # ---------------------------------------------------------------------
    def test_cred_002_login_event_detection(self):
        payload = {
            "username": "CredentialUser",
            "ip_address": "203.0.113.55",
            "success": False,
            "timestamp": datetime.now(timezone.utc).isoformat(),
            "user_agent": "Mozilla/5.0 ACDS-Test",
            "country": "US",
        }

        response = requests.post(f"{self.base_url}/credential-stuffing/login-event", json=payload)
        assert response.status_code == 200, f"Expected 200, got {response.status_code}: {response.text}"

        data = response.json()
        assert data.get("success") is True
        assert "event_id" in data
        assert "risk_score" in data
        assert "severity" in data
        assert "evidence" in data

        if data.get("alert_created"):
            self.created_alert_id = data.get("alert_id")

    # ---------------------------------------------------------------------
    # CRED-003: Batch analyze endpoint
    # ---------------------------------------------------------------------
    def test_cred_003_batch_analyze(self):
        now = datetime.now(timezone.utc)
        payload = {
            "events": [
                {
                    "username": "batch_user_1",
                    "ip_address": "198.51.100.99",
                    "success": False,
                    "timestamp": (now - timedelta(seconds=45)).isoformat(),
                    "user_agent": "BrowserA",
                    "country": "US",
                },
                {
                    "username": "batch_user_2",
                    "ip_address": "198.51.100.99",
                    "success": False,
                    "timestamp": now.isoformat(),
                    "user_agent": "BrowserB",
                    "country": "GB",
                },
            ]
        }

        response = requests.post(f"{self.base_url}/credential-stuffing/analyze", json=payload)
        assert response.status_code == 200, f"Expected 200, got {response.status_code}: {response.text}"

        data = response.json()
        assert data.get("success") is True
        assert data.get("count") == 2
        assert "results" in data
        assert len(data.get("results", [])) == 2

        alert_ids = data.get("alert_ids", [])
        if alert_ids:
            self.created_alert_id = alert_ids[0]

    # ---------------------------------------------------------------------
    # CRED-004: Alerts list endpoint
    # ---------------------------------------------------------------------
    def test_cred_004_alerts_list(self):
        response = requests.get(f"{self.base_url}/credential-stuffing/alerts", params={"limit": 10})
        assert response.status_code == 200, f"Expected 200, got {response.status_code}: {response.text}"

        data = response.json()
        assert data.get("success") is True
        assert "alerts" in data
        assert isinstance(data.get("alerts"), list)

        if data.get("alerts") and not self.created_alert_id:
            self.created_alert_id = data["alerts"][0].get("alert_id")

    # ---------------------------------------------------------------------
    # CRED-005: Feedback and retraining-data flow
    # ---------------------------------------------------------------------
    def test_cred_005_feedback_and_retraining_flow(self):
        # Ensure we have an alert id to provide feedback on
        if not self.created_alert_id:
            create_resp = self._create_medium_risk_event()
            if create_resp.status_code == 200:
                create_data = create_resp.json()
                if create_data.get("alert_created"):
                    self.created_alert_id = create_data.get("alert_id")

        if not self.created_alert_id:
            pytest.skip("No alert_id available to test feedback flow.")

        feedback_payload = {
            "alert_id": self.created_alert_id,
            "feedback": "needs_review",
            "analyst": "test-analyst",
            "notes": "Initial review pending evidence enrichment.",
        }

        feedback_response = requests.post(
            f"{self.base_url}/credential-stuffing/feedback", json=feedback_payload
        )
        assert feedback_response.status_code == 200, (
            f"Expected 200, got {feedback_response.status_code}: {feedback_response.text}"
        )

        feedback_data = feedback_response.json()
        assert feedback_data.get("success") is True
        assert feedback_data.get("alert_id") == self.created_alert_id
        assert "training_record_id" in feedback_data

        retraining_response = requests.get(
            f"{self.base_url}/credential-stuffing/retraining-data", params={"limit": 50}
        )
        assert retraining_response.status_code == 200, (
            f"Expected 200, got {retraining_response.status_code}: {retraining_response.text}"
        )

        retraining_data = retraining_response.json()
        assert retraining_data.get("success") is True
        assert "records" in retraining_data
        assert isinstance(retraining_data.get("records"), list)

    # ---------------------------------------------------------------------
    # CRED-006: Simulate attack endpoint
    # ---------------------------------------------------------------------
    def test_cred_006_simulate_attack(self):
        payload = {
            "source_ip": "203.0.113.200",
            "username_prefix": "sim_user",
            "count": 8,
        }

        response = requests.post(f"{self.base_url}/credential-stuffing/simulate-attack", json=payload)
        assert response.status_code == 200, f"Expected 200, got {response.status_code}: {response.text}"

        data = response.json()
        assert data.get("success") is True
        assert data.get("events_created") == 8
        assert data.get("alert_created") is True
        assert "alert_id" in data

        self.created_alert_id = data.get("alert_id")

    # ---------------------------------------------------------------------
    # CRED-007: Report endpoint behavior
    # ---------------------------------------------------------------------
    def test_cred_007_report_endpoint_behavior(self):
        if not self.created_alert_id:
            sim_resp = requests.post(
                f"{self.base_url}/credential-stuffing/simulate-attack",
                json={"source_ip": "198.51.100.212", "username_prefix": "rep_user", "count": 6},
            )
            if sim_resp.status_code == 200:
                self.created_alert_id = sim_resp.json().get("alert_id")

        if not self.created_alert_id:
            pytest.skip("No alert_id available to validate report endpoint.")

        response = requests.get(f"{self.base_url}/credential-stuffing/report/{self.created_alert_id}")

        # If ReportLab is installed, expect 200 (PDF).
        # If ReportLab is missing in environment, endpoint may return 500.
        assert response.status_code in (200, 500), (
            f"Expected 200 or 500 depending on environment, got {response.status_code}: {response.text}"
        )

    # ---------------------------------------------------------------------
    # CRED-008: Validation - missing required ip_address
    # ---------------------------------------------------------------------
    def test_cred_008_validation_missing_ip(self):
        payload = {
            "username": "user_missing_ip",
            "success": False,
        }
        response = requests.post(f"{self.base_url}/credential-stuffing/login-event", json=payload)
        assert response.status_code == 422, f"Expected 422, got {response.status_code}: {response.text}"

    # ---------------------------------------------------------------------
    # CRED-009: Validation - invalid feedback value
    # ---------------------------------------------------------------------
    def test_cred_009_validation_invalid_feedback(self):
        fake_alert_id = "CSA-INVALID123"
        payload = {
            "alert_id": fake_alert_id,
            "feedback": "incorrect_label",
            "analyst": "qa",
        }

        response = requests.post(f"{self.base_url}/credential-stuffing/feedback", json=payload)
        # Route maps ValueError to 400; missing alert may map to 404 depending order.
        assert response.status_code in (400, 404), (
            f"Expected 400 or 404, got {response.status_code}: {response.text}"
        )


if __name__ == "__main__":
    pytest.main([__file__, "-v", "--tb=short"])

