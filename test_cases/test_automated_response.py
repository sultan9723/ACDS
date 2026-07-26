"""
ACDS Test Cases - Automated Response Module
===========================================
Python test cases for Module 7 (Automated Response).

Scope:
- Phishing response controls (blocked senders, quarantine, response history)
- Ransomware response orchestration (recommend, action, orchestrate, history)
- Ransomware response state endpoints (blocked hashes, isolated hosts)
"""

import os
import time

import pytest
import requests


BASE_URL = os.getenv("ACDS_API_BASE_URL", "http://127.0.0.1:8000/api/v1")


class TestAutomatedResponse:
    """Module 7 - automated response test suite."""

    @pytest.fixture(autouse=True)
    def setup(self):
        self.base_url = BASE_URL
        self.sender_to_block = f"auto-response-{int(time.time())}@example.com"
        self.ransom_incident_id = f"RAN_TEST_{int(time.time())}"
        yield

    # ---------------------------------------------------------------------
    # RESP-001: Get phishing blocked senders list
    # ---------------------------------------------------------------------
    def test_resp_001_get_blocked_senders(self):
        response = requests.get(f"{self.base_url}/threats/blocked-senders")
        assert response.status_code == 200, f"Expected 200, got {response.status_code}: {response.text}"

        data = response.json()
        assert data.get("success") is True
        assert "blocked_senders" in data
        assert isinstance(data.get("blocked_senders"), list)

    # ---------------------------------------------------------------------
    # RESP-002: Block sender and verify listing
    # ---------------------------------------------------------------------
    def test_resp_002_block_sender(self):
        block_resp = requests.post(
            f"{self.base_url}/threats/blocked-senders",
            params={"email": self.sender_to_block, "reason": "automated test"},
        )
        assert block_resp.status_code == 200, f"Expected 200, got {block_resp.status_code}: {block_resp.text}"

        block_data = block_resp.json()
        assert "success" in block_data

        list_resp = requests.get(f"{self.base_url}/threats/blocked-senders")
        assert list_resp.status_code == 200
        listed = list_resp.json().get("blocked_senders", [])
        assert self.sender_to_block in listed

    # ---------------------------------------------------------------------
    # RESP-003: Unblock sender
    # ---------------------------------------------------------------------
    def test_resp_003_unblock_sender(self):
        requests.post(
            f"{self.base_url}/threats/blocked-senders",
            params={"email": self.sender_to_block, "reason": "setup for unblock"},
        )

        response = requests.delete(f"{self.base_url}/threats/blocked-senders/{self.sender_to_block}")
        assert response.status_code == 200, f"Expected 200, got {response.status_code}: {response.text}"

        data = response.json()
        assert data.get("success") in (True, False)

    # ---------------------------------------------------------------------
    # RESP-004: Get quarantine list
    # ---------------------------------------------------------------------
    def test_resp_004_get_quarantine_list(self):
        response = requests.get(f"{self.base_url}/threats/quarantine")
        assert response.status_code == 200, f"Expected 200, got {response.status_code}: {response.text}"

        data = response.json()
        assert data.get("success") is True
        assert "files" in data
        assert isinstance(data.get("files"), list)

    # ---------------------------------------------------------------------
    # RESP-005: Restore from quarantine behavior
    # ---------------------------------------------------------------------
    def test_resp_005_restore_from_quarantine_behavior(self):
        response = requests.post(
            f"{self.base_url}/threats/quarantine/restore",
            params={"filename": "nonexistent_file.eml", "destination": "C:/temp"},
        )
        # If nonexistent, expected 404; if test env has this file then 200 is acceptable.
        assert response.status_code in (200, 404), (
            f"Expected 200 or 404, got {response.status_code}: {response.text}"
        )

    # ---------------------------------------------------------------------
    # RESP-006: Get phishing response history
    # ---------------------------------------------------------------------
    def test_resp_006_get_phishing_response_history(self):
        response = requests.get(f"{self.base_url}/threats/response-history", params={"limit": 20})
        assert response.status_code == 200, f"Expected 200, got {response.status_code}: {response.text}"

        data = response.json()
        assert data.get("success") is True
        assert "history" in data
        assert isinstance(data.get("history"), list)

    # ---------------------------------------------------------------------
    # RESP-007: Ransomware recommendations endpoint
    # ---------------------------------------------------------------------
    def test_resp_007_ransomware_response_recommend(self):
        payload = {
            "threat": {
                "incident_id": self.ransom_incident_id,
                "severity": "HIGH",
                "risk_score": 82,
                "threat_type": "ransomware",
                "source_host": "host-auto-response",
            }
        }

        response = requests.post(f"{self.base_url}/ransomware/response/recommend", json=payload)
        assert response.status_code == 200, f"Expected 200, got {response.status_code}: {response.text}"

        data = response.json()
        assert data.get("success") is True
        assert data.get("safe_mode") is True
        assert "recommendations" in data

    # ---------------------------------------------------------------------
    # RESP-008: Ransomware record response action
    # ---------------------------------------------------------------------
    def test_resp_008_ransomware_response_action(self):
        payload = {
            "action_type": "isolate_host",
            "incident_id": self.ransom_incident_id,
            "severity": "CRITICAL",
            "confidence": 0.93,
            "source_host": "host-auto-response",
            "requested_by": "pytest-suite",
        }

        response = requests.post(f"{self.base_url}/ransomware/response/action", json=payload)
        assert response.status_code == 200, f"Expected 200, got {response.status_code}: {response.text}"

        data = response.json()
        assert data.get("success") is True
        assert data.get("safe_mode") is True
        assert "action" in data

    # ---------------------------------------------------------------------
    # RESP-009: Ransomware orchestrated response
    # ---------------------------------------------------------------------
    def test_resp_009_ransomware_response_orchestrate(self):
        payload = {
            "threat": {
                "incident_id": self.ransom_incident_id,
                "severity": "HIGH",
                "risk_score": 75,
                "threat_type": "ransomware",
                "source_host": "host-orchestrate",
            },
            "actions": ["isolate_host"],
            "requested_by": "pytest-suite",
        }

        response = requests.post(f"{self.base_url}/ransomware/response/orchestrate", json=payload)
        assert response.status_code == 200, f"Expected 200, got {response.status_code}: {response.text}"

        data = response.json()
        assert "success" in data

    # ---------------------------------------------------------------------
    # RESP-010: Ransomware response history + state endpoints
    # ---------------------------------------------------------------------
    def test_resp_010_ransomware_response_history_and_state(self):
        history_resp = requests.get(
            f"{self.base_url}/ransomware/response/history",
            params={"incident_id": self.ransom_incident_id, "limit": 20},
        )
        assert history_resp.status_code == 200, (
            f"Expected 200, got {history_resp.status_code}: {history_resp.text}"
        )
        history_data = history_resp.json()
        assert history_data.get("success") is True
        assert "history" in history_data

        hashes_resp = requests.get(f"{self.base_url}/ransomware/blocked-hashes")
        assert hashes_resp.status_code == 200, (
            f"Expected 200, got {hashes_resp.status_code}: {hashes_resp.text}"
        )
        hashes_data = hashes_resp.json()
        assert hashes_data.get("success") is True
        assert "blocked_hashes" in hashes_data

        hosts_resp = requests.get(f"{self.base_url}/ransomware/isolated-hosts")
        assert hosts_resp.status_code == 200, (
            f"Expected 200, got {hosts_resp.status_code}: {hosts_resp.text}"
        )
        hosts_data = hosts_resp.json()
        assert hosts_data.get("success") is True
        assert "isolated_hosts" in hosts_data


if __name__ == "__main__":
    pytest.main([__file__, "-v", "--tb=short"])

