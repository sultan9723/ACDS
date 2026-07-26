"""
ACDS Test Cases - Dashboard Visualization Module
================================================
Python test cases for Module 8 (Dashboard Visualization).

Scope:
- Core dashboard widgets and KPI endpoints
- Threat feed and chart datasets
- Activity logs and timeline endpoints
- Alerts and system health widgets
- Frontend compatibility routes
"""

import os
import pytest
import requests


BASE_URL = os.getenv("ACDS_API_BASE_URL", "http://127.0.0.1:8000/api/v1")


class TestDashboardVisualization:
    """Module 8 - dashboard visualization test suite."""

    @pytest.fixture(autouse=True)
    def setup(self):
        self.base_url = BASE_URL
        yield

    # ---------------------------------------------------------------------
    # DASH-001: Main dashboard stats
    # ---------------------------------------------------------------------
    def test_dash_001_dashboard_stats(self):
        response = requests.get(f"{self.base_url}/dashboard/stats")
        assert response.status_code == 200, f"Expected 200, got {response.status_code}: {response.text}"

        data = response.json()
        assert data.get("success") is True
        assert "stats" in data
        assert "total_threats" in data
        assert "active_threats" in data

    # ---------------------------------------------------------------------
    # DASH-002: Recent threats (primary feed)
    # ---------------------------------------------------------------------
    def test_dash_002_recent_threats(self):
        response = requests.get(f"{self.base_url}/dashboard/threats/recent", params={"limit": 10})
        assert response.status_code == 200, f"Expected 200, got {response.status_code}: {response.text}"

        data = response.json()
        assert data.get("success") is True
        assert "threats" in data
        assert isinstance(data.get("threats"), list)
        assert "count" in data

    # ---------------------------------------------------------------------
    # DASH-003: Recent threats compatibility route
    # ---------------------------------------------------------------------
    def test_dash_003_recent_threats_compat_route(self):
        response = requests.get(f"{self.base_url}/dashboard/recent-threats", params={"limit": 10})
        assert response.status_code == 200, f"Expected 200, got {response.status_code}: {response.text}"

        data = response.json()
        assert data.get("success") is True
        assert "threats" in data

    # ---------------------------------------------------------------------
    # DASH-004: Threat timeline chart data
    # ---------------------------------------------------------------------
    def test_dash_004_threats_timeline(self):
        response = requests.get(f"{self.base_url}/dashboard/threats/timeline", params={"days": 7})
        assert response.status_code == 200, f"Expected 200, got {response.status_code}: {response.text}"

        data = response.json()
        assert data.get("success") is True
        assert "timeline" in data
        assert isinstance(data.get("timeline"), list)

    # ---------------------------------------------------------------------
    # DASH-005: Threat severity breakdown
    # ---------------------------------------------------------------------
    def test_dash_005_threats_by_severity(self):
        response = requests.get(f"{self.base_url}/dashboard/threats/by-severity")
        assert response.status_code == 200, f"Expected 200, got {response.status_code}: {response.text}"

        data = response.json()
        assert data.get("success") is True
        assert "breakdown" in data
        assert isinstance(data.get("breakdown"), dict)

    # ---------------------------------------------------------------------
    # DASH-006: Threat type breakdown
    # ---------------------------------------------------------------------
    def test_dash_006_threats_by_type(self):
        response = requests.get(f"{self.base_url}/dashboard/threats/by-type")
        assert response.status_code == 200, f"Expected 200, got {response.status_code}: {response.text}"

        data = response.json()
        assert data.get("success") is True
        assert "breakdown" in data
        assert isinstance(data.get("breakdown"), dict)

    # ---------------------------------------------------------------------
    # DASH-007: Activity chart endpoint
    # ---------------------------------------------------------------------
    def test_dash_007_activity_chart(self):
        response = requests.get(f"{self.base_url}/dashboard/activity")
        assert response.status_code == 200, f"Expected 200, got {response.status_code}: {response.text}"

        data = response.json()
        assert data.get("success") is True
        assert "activity" in data
        assert isinstance(data.get("activity"), list)

    # ---------------------------------------------------------------------
    # DASH-008: Activity logs endpoint
    # ---------------------------------------------------------------------
    def test_dash_008_activity_logs(self):
        response = requests.get(f"{self.base_url}/dashboard/activity-logs", params={"limit": 20})
        assert response.status_code == 200, f"Expected 200, got {response.status_code}: {response.text}"

        data = response.json()
        assert data.get("success") is True
        assert "logs" in data
        assert isinstance(data.get("logs"), list)

    # ---------------------------------------------------------------------
    # DASH-009: Recent activity widget endpoint
    # ---------------------------------------------------------------------
    def test_dash_009_recent_activity_widget(self):
        response = requests.get(f"{self.base_url}/dashboard/activity/recent", params={"limit": 15})
        assert response.status_code == 200, f"Expected 200, got {response.status_code}: {response.text}"

        data = response.json()
        assert data.get("success") is True
        assert "activities" in data
        assert isinstance(data.get("activities"), list)

    # ---------------------------------------------------------------------
    # DASH-010: Alerts widget endpoint
    # ---------------------------------------------------------------------
    def test_dash_010_alerts_widget(self):
        response = requests.get(f"{self.base_url}/dashboard/alerts")
        assert response.status_code == 200, f"Expected 200, got {response.status_code}: {response.text}"

        data = response.json()
        assert data.get("success") is True
        assert "alerts" in data
        assert isinstance(data.get("alerts"), list)
        assert "unread_count" in data

    # ---------------------------------------------------------------------
    # DASH-011: Model performance endpoint
    # ---------------------------------------------------------------------
    def test_dash_011_model_performance(self):
        response = requests.get(f"{self.base_url}/dashboard/model/performance")
        assert response.status_code == 200, f"Expected 200, got {response.status_code}: {response.text}"

        data = response.json()
        assert data.get("success") is True
        assert "performance" in data
        assert "accuracy" in data["performance"]

    # ---------------------------------------------------------------------
    # DASH-012: Model status compatibility endpoint
    # ---------------------------------------------------------------------
    def test_dash_012_model_status_compat(self):
        response = requests.get(f"{self.base_url}/dashboard/model-status")
        assert response.status_code == 200, f"Expected 200, got {response.status_code}: {response.text}"

        data = response.json()
        assert data.get("success") is True
        assert "model_loaded" in data
        assert "accuracy" in data

    # ---------------------------------------------------------------------
    # DASH-013: System health endpoint
    # ---------------------------------------------------------------------
    def test_dash_013_system_health(self):
        response = requests.get(f"{self.base_url}/dashboard/system/health")
        assert response.status_code == 200, f"Expected 200, got {response.status_code}: {response.text}"

        data = response.json()
        assert data.get("success") is True
        assert "health" in data
        assert "overall_status" in data["health"]


if __name__ == "__main__":
    pytest.main([__file__, "-v", "--tb=short"])

