"""
ACDS Test Cases - AI Report Generation Module
=============================================
Python test cases for Module 9 (AI Report Generation).

Scope:
- AI report generation endpoint (/reports/generate)
- Report catalog endpoints (/reports/types, /reports/list)
- Incident report metadata/list/download/delete flows
- Legacy compatibility endpoints under /reports/detail/*
"""

from datetime import datetime, timezone, timedelta
import os
import time

import pytest
import requests


BASE_URL = os.getenv("ACDS_API_BASE_URL", "http://127.0.0.1:8000/api/v1")


class TestAIReportGeneration:
    """Module 9 - AI report generation test suite."""

    @pytest.fixture(autouse=True)
    def setup(self):
        self.base_url = BASE_URL
        self.known_report_id = None
        yield

    # ---------------------------------------------------------------------
    # REP-001: Get available report types
    # ---------------------------------------------------------------------
    def test_rep_001_get_report_types(self):
        response = requests.get(f"{self.base_url}/reports/types")
        assert response.status_code == 200, f"Expected 200, got {response.status_code}: {response.text}"

        data = response.json()
        assert data.get("success") is True
        assert "report_types" in data
        assert isinstance(data.get("report_types"), list)
        assert len(data.get("report_types")) > 0

    # ---------------------------------------------------------------------
    # REP-002: Generate AI threat summary report
    # ---------------------------------------------------------------------
    def test_rep_002_generate_ai_report(self):
        payload = {
            "report_type": "threat_summary",
            "start_date": (datetime.now(timezone.utc) - timedelta(days=7)).isoformat(),
            "end_date": datetime.now(timezone.utc).isoformat(),
            "include_details": True,
            "format": "json",
        }

        response = requests.post(f"{self.base_url}/reports/generate", json=payload)
        assert response.status_code == 200, f"Expected 200, got {response.status_code}: {response.text}"

        data = response.json()
        assert data.get("success") is True
        assert "report" in data

    # ---------------------------------------------------------------------
    # REP-003: Generate AI executive summary report
    # ---------------------------------------------------------------------
    def test_rep_003_generate_executive_report(self):
        payload = {
            "report_type": "executive_summary",
            "include_details": False,
            "format": "json",
        }

        response = requests.post(f"{self.base_url}/reports/generate", json=payload)
        assert response.status_code == 200, f"Expected 200, got {response.status_code}: {response.text}"

        data = response.json()
        assert data.get("success") is True
        assert "report" in data

    # ---------------------------------------------------------------------
    # REP-004: Validation - invalid report type
    # ---------------------------------------------------------------------
    def test_rep_004_invalid_report_type_validation(self):
        payload = {
            "report_type": "unknown_report_type",
            "include_details": True,
            "format": "json",
        }

        response = requests.post(f"{self.base_url}/reports/generate", json=payload)
        assert response.status_code == 422, f"Expected 422, got {response.status_code}: {response.text}"

    # ---------------------------------------------------------------------
    # REP-005: List incident reports
    # ---------------------------------------------------------------------
    def test_rep_005_list_incident_reports(self):
        response = requests.get(f"{self.base_url}/reports/incidents", params={"limit": 20})
        assert response.status_code == 200, f"Expected 200, got {response.status_code}: {response.text}"

        data = response.json()
        assert data.get("success") is True
        assert "reports" in data
        assert isinstance(data.get("reports"), list)

        reports = data.get("reports", [])
        if reports:
            self.known_report_id = reports[0].get("report_id")

    # ---------------------------------------------------------------------
    # REP-006: Legacy list compatibility endpoint
    # ---------------------------------------------------------------------
    def test_rep_006_legacy_reports_list(self):
        response = requests.get(f"{self.base_url}/reports/list", params={"limit": 10})
        assert response.status_code == 200, f"Expected 200, got {response.status_code}: {response.text}"

        data = response.json()
        assert data.get("success") is True
        assert "reports" in data

    # ---------------------------------------------------------------------
    # REP-007: Get specific incident report metadata
    # ---------------------------------------------------------------------
    def test_rep_007_get_incident_report_metadata(self):
        if not self.known_report_id:
            list_resp = requests.get(f"{self.base_url}/reports/incidents", params={"limit": 1})
            if list_resp.status_code == 200 and list_resp.json().get("reports"):
                self.known_report_id = list_resp.json()["reports"][0].get("report_id")

        if not self.known_report_id:
            pytest.skip("No incident report metadata available in environment.")

        response = requests.get(f"{self.base_url}/reports/incidents/{self.known_report_id}")
        assert response.status_code == 200, f"Expected 200, got {response.status_code}: {response.text}"

        data = response.json()
        assert data.get("success") is True
        assert "report" in data

    # ---------------------------------------------------------------------
    # REP-008: Download incident PDF report behavior
    # ---------------------------------------------------------------------
    def test_rep_008_download_incident_report_behavior(self):
        if not self.known_report_id:
            list_resp = requests.get(f"{self.base_url}/reports/incidents", params={"limit": 1})
            if list_resp.status_code == 200 and list_resp.json().get("reports"):
                self.known_report_id = list_resp.json()["reports"][0].get("report_id")

        if not self.known_report_id:
            pytest.skip("No incident report available to test download.")

        response = requests.get(f"{self.base_url}/reports/incidents/{self.known_report_id}/download")
        # Depending on environment/file existence: 200 for found, 404 for missing file
        assert response.status_code in (200, 404), (
            f"Expected 200 or 404, got {response.status_code}: {response.text}"
        )

    # ---------------------------------------------------------------------
    # REP-009: Legacy detail endpoint compatibility
    # ---------------------------------------------------------------------
    def test_rep_009_legacy_detail_endpoint(self):
        if not self.known_report_id:
            list_resp = requests.get(f"{self.base_url}/reports/incidents", params={"limit": 1})
            if list_resp.status_code == 200 and list_resp.json().get("reports"):
                self.known_report_id = list_resp.json()["reports"][0].get("report_id")

        if not self.known_report_id:
            pytest.skip("No incident report available for legacy detail test.")

        response = requests.get(f"{self.base_url}/reports/detail/{self.known_report_id}")
        assert response.status_code in (200, 404), (
            f"Expected 200 or 404, got {response.status_code}: {response.text}"
        )

    # ---------------------------------------------------------------------
    # REP-010: Export endpoint behavior (non-PDF format)
    # ---------------------------------------------------------------------
    def test_rep_010_export_non_pdf_behavior(self):
        if not self.known_report_id:
            list_resp = requests.get(f"{self.base_url}/reports/incidents", params={"limit": 1})
            if list_resp.status_code == 200 and list_resp.json().get("reports"):
                self.known_report_id = list_resp.json()["reports"][0].get("report_id")

        if not self.known_report_id:
            pytest.skip("No report available to test export endpoint.")

        response = requests.get(
            f"{self.base_url}/reports/detail/{self.known_report_id}/export",
            params={"format": "json"},
        )
        assert response.status_code in (200, 404), (
            f"Expected 200 or 404, got {response.status_code}: {response.text}"
        )

    # ---------------------------------------------------------------------
    # REP-011: Delete report behavior
    # ---------------------------------------------------------------------
    def test_rep_011_delete_report_behavior(self):
        fake_id = f"NON_EXISTING_REPORT_{int(time.time())}"
        response = requests.delete(f"{self.base_url}/reports/incidents/{fake_id}")
        assert response.status_code in (404, 500), (
            f"Expected 404 or 500, got {response.status_code}: {response.text}"
        )


if __name__ == "__main__":
    pytest.main([__file__, "-v", "--tb=short"])

