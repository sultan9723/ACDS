"""
ACDS Test Cases - Analyst Feedback Module
=========================================
Python test cases for Module 10 (Analyst Feedback).

Scope:
- Feedback submission and retrieval
- Review workflow (approve/reject)
- Summary/stats endpoints
- Retraining dataset endpoints
- Mark-used-for-retraining flow
- Validation behavior
"""

import os
import time

import pytest
import requests


BASE_URL = os.getenv("ACDS_API_BASE_URL", "http://127.0.0.1:8000/api/v1")


class TestAnalystFeedback:
    """Module 10 - analyst feedback test suite."""

    @pytest.fixture(autouse=True)
    def setup(self):
        self.base_url = BASE_URL
        self.feedback_id = None
        yield

    # ---------------------------------------------------------------------
    # FDB-001: Submit feedback (false positive)
    # ---------------------------------------------------------------------
    def test_fdb_001_submit_feedback_false_positive(self):
        payload = {
            "scan_id": f"SCAN-{int(time.time())}",
            "feedback_type": "false_positive",
            "correct_label": False,
            "correct_severity": "LOW",
            "comment": "Legitimate internal email was flagged.",
            "email_content": "Hi team, this is the weekly status update.",
        }

        response = requests.post(f"{self.base_url}/feedback/", json=payload)
        assert response.status_code == 200, f"Expected 200, got {response.status_code}: {response.text}"

        data = response.json()
        assert data.get("success") is True
        assert "data" in data
        assert "feedback_id" in data["data"]

        self.feedback_id = data["data"]["feedback_id"]

    # ---------------------------------------------------------------------
    # FDB-002: Submit feedback (false negative)
    # ---------------------------------------------------------------------
    def test_fdb_002_submit_feedback_false_negative(self):
        payload = {
            "scan_id": f"SCAN-{int(time.time())+1}",
            "feedback_type": "false_negative",
            "correct_label": True,
            "correct_severity": "HIGH",
            "comment": "Phishing email bypassed detection.",
            "email_content": "Urgent: Verify your payroll account now.",
        }

        response = requests.post(f"{self.base_url}/feedback/", json=payload)
        assert response.status_code == 200, f"Expected 200, got {response.status_code}: {response.text}"

        data = response.json()
        assert data.get("success") is True

    # ---------------------------------------------------------------------
    # FDB-003: List feedback entries
    # ---------------------------------------------------------------------
    def test_fdb_003_list_feedback(self):
        response = requests.get(f"{self.base_url}/feedback/", params={"limit": 20})
        assert response.status_code == 200, f"Expected 200, got {response.status_code}: {response.text}"

        data = response.json()
        assert data.get("success") is True
        assert "feedback" in data
        assert isinstance(data.get("feedback"), list)

        feedback_list = data.get("feedback", [])
        if feedback_list and not self.feedback_id:
            self.feedback_id = feedback_list[0].get("feedback_id")

    # ---------------------------------------------------------------------
    # FDB-004: Get specific feedback by id
    # ---------------------------------------------------------------------
    def test_fdb_004_get_feedback_by_id(self):
        if not self.feedback_id:
            create_resp = requests.post(
                f"{self.base_url}/feedback/",
                json={
                    "scan_id": f"SCAN-{int(time.time())+2}",
                    "feedback_type": "general_feedback",
                    "comment": "Manual check required.",
                },
            )
            if create_resp.status_code == 200:
                self.feedback_id = create_resp.json().get("data", {}).get("feedback_id")

        if not self.feedback_id:
            pytest.skip("No feedback_id available to fetch detail.")

        response = requests.get(f"{self.base_url}/feedback/{self.feedback_id}")
        assert response.status_code == 200, f"Expected 200, got {response.status_code}: {response.text}"

        data = response.json()
        assert data.get("success") is True
        assert "feedback" in data
        assert data["feedback"].get("feedback_id") == self.feedback_id

    # ---------------------------------------------------------------------
    # FDB-005: Review feedback (approve)
    # ---------------------------------------------------------------------
    def test_fdb_005_review_feedback_approve(self):
        if not self.feedback_id:
            create_resp = requests.post(
                f"{self.base_url}/feedback/",
                json={
                    "scan_id": f"SCAN-{int(time.time())+3}",
                    "feedback_type": "correct_detection",
                    "comment": "Detection was accurate.",
                },
            )
            if create_resp.status_code == 200:
                self.feedback_id = create_resp.json().get("data", {}).get("feedback_id")

        if not self.feedback_id:
            pytest.skip("No feedback_id available to review.")

        payload = {
            "approved": True,
            "review_notes": "Validated by analyst.",
        }
        response = requests.post(f"{self.base_url}/feedback/{self.feedback_id}/review", json=payload)
        assert response.status_code == 200, f"Expected 200, got {response.status_code}: {response.text}"

        data = response.json()
        assert data.get("success") is True
        assert data.get("status") in ("approved", "rejected")

    # ---------------------------------------------------------------------
    # FDB-006: Feedback summary stats
    # ---------------------------------------------------------------------
    def test_fdb_006_feedback_summary(self):
        response = requests.get(f"{self.base_url}/feedback/summary/stats")
        assert response.status_code == 200, f"Expected 200, got {response.status_code}: {response.text}"

        data = response.json()
        # Route is annotated with FeedbackSummary model fields
        assert "total_feedback" in data
        assert "pending_review" in data
        assert "by_type" in data
        assert "retrain_recommended" in data

    # ---------------------------------------------------------------------
    # FDB-007: Feedback service stats
    # ---------------------------------------------------------------------
    def test_fdb_007_feedback_service_stats(self):
        response = requests.get(f"{self.base_url}/feedback/stats/service")
        assert response.status_code == 200, f"Expected 200, got {response.status_code}: {response.text}"

        data = response.json()
        assert data.get("success") is True
        assert "stats" in data

    # ---------------------------------------------------------------------
    # FDB-008: Retraining data retrieval
    # ---------------------------------------------------------------------
    def test_fdb_008_get_retraining_data(self):
        response = requests.get(f"{self.base_url}/feedback/retraining/data")
        assert response.status_code == 200, f"Expected 200, got {response.status_code}: {response.text}"

        data = response.json()
        assert data.get("success") is True
        assert "retraining_data" in data

    # ---------------------------------------------------------------------
    # FDB-009: Mark feedback used for retraining
    # ---------------------------------------------------------------------
    def test_fdb_009_mark_feedback_used_for_retraining(self):
        if not self.feedback_id:
            create_resp = requests.post(
                f"{self.base_url}/feedback/",
                json={
                    "scan_id": f"SCAN-{int(time.time())+4}",
                    "feedback_type": "general_feedback",
                    "comment": "Mark this as used test.",
                },
            )
            if create_resp.status_code == 200:
                self.feedback_id = create_resp.json().get("data", {}).get("feedback_id")

        if not self.feedback_id:
            pytest.skip("No feedback_id available for mark-used test.")

        payload = [self.feedback_id]
        response = requests.post(f"{self.base_url}/feedback/retraining/mark-used", json=payload)
        assert response.status_code == 200, f"Expected 200, got {response.status_code}: {response.text}"

        data = response.json()
        assert data.get("success") is True
        assert "count" in data

    # ---------------------------------------------------------------------
    # FDB-010: Validation - invalid feedback type
    # ---------------------------------------------------------------------
    def test_fdb_010_invalid_feedback_type_validation(self):
        payload = {
            "scan_id": f"SCAN-{int(time.time())+5}",
            "feedback_type": "invalid_feedback_kind",
            "comment": "Should fail validation",
        }

        response = requests.post(f"{self.base_url}/feedback/", json=payload)
        assert response.status_code == 422, f"Expected 422, got {response.status_code}: {response.text}"


if __name__ == "__main__":
    pytest.main([__file__, "-v", "--tb=short"])

