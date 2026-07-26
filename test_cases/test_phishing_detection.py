"""
ACDS Test Cases - Phishing Detection Module
==========================================
Python test cases for Module 3 (Phishing Detection).

Scope:
- Full phishing scan pipeline
- Batch scan
- Quick detection and explainability endpoints
- Stats/model info endpoints
- Incident retrieval and state transition
- Basic input validation
"""

from datetime import datetime, timezone
import os
import time

import pytest
import requests


BASE_URL = os.getenv("ACDS_API_BASE_URL", "http://127.0.0.1:8000/api/v1")


class TestPhishingDetection:
    """Module 3 - phishing detection test suite."""

    @pytest.fixture(autouse=True)
    def setup(self):
        self.base_url = BASE_URL
        yield

    # ---------------------------------------------------------------------
    # PHISH-001: Full phishing scan pipeline
    # ---------------------------------------------------------------------
    def test_phish_001_full_scan_pipeline(self):
        payload = {
            "content": "URGENT: Your account is suspended. Verify now at http://verify-now.example.com",
            "sender": "security@fakebank.com",
            "subject": "Immediate Verification Required",
            "recipient": "employee@company.com",
            "email_id": f"phish_full_{int(time.time())}",
        }

        response = requests.post(f"{self.base_url}/threats/scan", json=payload)
        assert response.status_code == 200, f"Expected 200, got {response.status_code}: {response.text}"

        data = response.json()
        assert data.get("success") is True
        result = data.get("result", {})
        assert "pipeline_results" in result
        assert "detection" in result["pipeline_results"]

    # ---------------------------------------------------------------------
    # PHISH-002: Batch phishing scan
    # ---------------------------------------------------------------------
    def test_phish_002_batch_scan(self):
        payload = {
            "emails": [
                {
                    "content": "Please review attached quarterly report.",
                    "sender": "manager@company.com",
                    "subject": "Q4 Report",
                },
                {
                    "content": "Verify your payroll now at http://payroll-alert.example.com",
                    "sender": "hr-security@alerts.com",
                    "subject": "Payroll Access Alert",
                },
            ]
        }

        response = requests.post(f"{self.base_url}/threats/scan/batch", json=payload)
        assert response.status_code == 200, f"Expected 200, got {response.status_code}: {response.text}"

        data = response.json()
        assert data.get("success") is True
        assert data.get("summary", {}).get("total_scanned") == 2
        assert len(data.get("results", [])) == 2

    # ---------------------------------------------------------------------
    # PHISH-003: Quick detection scan
    # ---------------------------------------------------------------------
    def test_phish_003_quick_scan(self):
        payload = {
            "content": "Reset your password immediately: http://malicious-reset.example.com"
        }

        response = requests.post(f"{self.base_url}/threats/scan/quick", json=payload)
        assert response.status_code == 200, f"Expected 200, got {response.status_code}: {response.text}"

        data = response.json()
        assert data.get("success") is True
        result = data.get("result", {})
        assert "is_phishing" in result
        assert "confidence" in result
        assert "severity" in result

    # ---------------------------------------------------------------------
    # PHISH-004: Detection + explainability scan
    # ---------------------------------------------------------------------
    def test_phish_004_scan_with_explanation(self):
        payload = {
            "content": "Your mailbox is full. Click here to upgrade quota: http://mail-upgrade.example.com",
            "email_id": f"phish_explain_{int(time.time())}",
        }

        response = requests.post(f"{self.base_url}/threats/scan/explain", json=payload)
        assert response.status_code == 200, f"Expected 200, got {response.status_code}: {response.text}"

        data = response.json()
        assert data.get("success") is True
        assert "detection" in data
        assert "explainability" in data

    # ---------------------------------------------------------------------
    # PHISH-005: Deprecated respond endpoint compatibility
    # ---------------------------------------------------------------------
    def test_phish_005_scan_respond_compatibility(self):
        payload = {
            "content": "Suspicious login attempt detected. Verify identity now.",
            "sender": "no-reply@account-protect.com",
            "subject": "Security Verification",
        }

        response = requests.post(f"{self.base_url}/threats/scan/respond", json=payload)
        assert response.status_code == 200, f"Expected 200, got {response.status_code}: {response.text}"

        data = response.json()
        assert data.get("success") is True
        assert "result" in data

    # ---------------------------------------------------------------------
    # PHISH-006: Detection stats endpoint
    # ---------------------------------------------------------------------
    def test_phish_006_detection_stats(self):
        response = requests.get(f"{self.base_url}/threats/stats")
        assert response.status_code == 200, f"Expected 200, got {response.status_code}: {response.text}"

        data = response.json()
        assert data.get("success") is True
        assert "stats" in data
        stats = data["stats"]
        assert "orchestrator" in stats
        assert "detection" in stats

    # ---------------------------------------------------------------------
    # PHISH-007: Model info endpoint
    # ---------------------------------------------------------------------
    def test_phish_007_model_info(self):
        response = requests.get(f"{self.base_url}/threats/model/info")
        assert response.status_code == 200, f"Expected 200, got {response.status_code}: {response.text}"

        data = response.json()
        assert data.get("success") is True
        assert "model_info" in data

    # ---------------------------------------------------------------------
    # PHISH-008: Incidents list endpoint
    # ---------------------------------------------------------------------
    def test_phish_008_incidents_list(self):
        response = requests.get(f"{self.base_url}/threats/incidents", params={"limit": 5})
        assert response.status_code == 200, f"Expected 200, got {response.status_code}: {response.text}"

        data = response.json()
        assert data.get("success") is True
        assert "incidents" in data
        assert isinstance(data.get("incidents"), list)

    # ---------------------------------------------------------------------
    # PHISH-009: Incident detail + lifecycle transition
    # ---------------------------------------------------------------------
    def test_phish_009_incident_detail_and_state_update(self):
        create_payload = {
            "content": "Please validate account security with this link http://secure-check.example.com",
            "email_id": f"phish_incident_{int(time.time())}",
        }
        create_resp = requests.post(f"{self.base_url}/threats/scan", json=create_payload)
        assert create_resp.status_code == 200, f"Expected 200, got {create_resp.status_code}: {create_resp.text}"

        incident_id = create_resp.json().get("result", {}).get("incident_id")
        assert incident_id, "incident_id not returned from scan result"

        get_resp = requests.get(f"{self.base_url}/threats/incidents/{incident_id}")
        assert get_resp.status_code == 200, f"Expected 200, got {get_resp.status_code}: {get_resp.text}"
        assert get_resp.json().get("success") is True

        update_resp = requests.patch(
            f"{self.base_url}/threats/incidents/{incident_id}/state",
            params={"new_state": "resolved"},
        )
        assert update_resp.status_code == 200, f"Expected 200, got {update_resp.status_code}: {update_resp.text}"
        update_data = update_resp.json()
        assert update_data.get("success") is True
        assert update_data.get("new_state") == "resolved"

    # ---------------------------------------------------------------------
    # PHISH-010: Invalid incident state rejected
    # ---------------------------------------------------------------------
    def test_phish_010_invalid_incident_state_rejected(self):
        fake_incident = "INC_FAKE_12345"
        response = requests.patch(
            f"{self.base_url}/threats/incidents/{fake_incident}/state",
            params={"new_state": "invalid_state"},
        )
        assert response.status_code == 400, f"Expected 400, got {response.status_code}: {response.text}"

    # ---------------------------------------------------------------------
    # PHISH-011: Validation for missing required content
    # ---------------------------------------------------------------------
    def test_phish_011_required_content_validation(self):
        payload = {
            "sender": "test@company.com",
            "subject": "No content provided",
        }
        response = requests.post(f"{self.base_url}/threats/scan", json=payload)
        assert response.status_code == 422, f"Expected 422, got {response.status_code}: {response.text}"

    # ---------------------------------------------------------------------
    # PHISH-012: Quick scan empty content rejected
    # ---------------------------------------------------------------------
    def test_phish_012_quick_scan_empty_content_rejected(self):
        payload = {"content": ""}
        response = requests.post(f"{self.base_url}/threats/scan/quick", json=payload)
        assert response.status_code == 422, f"Expected 422, got {response.status_code}: {response.text}"


if __name__ == "__main__":
    pytest.main([__file__, "-v", "--tb=short"])

