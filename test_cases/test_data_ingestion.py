"""
ACDS Test Cases - Data Ingestion Module
======================================
Python test cases for Module 2 (Data Ingestion).

Scope:
- Ingestion entry points across phishing, ransomware, malware, and credential stuffing
- Single-item and batch ingestion
- Basic schema validation / required-field enforcement

Notes:
- These are API-level ingestion tests.
- Backend should be running at http://127.0.0.1:8000
"""

from datetime import datetime, timezone, timedelta
import os
import time

import pytest
import requests


BASE_URL = os.getenv("ACDS_API_BASE_URL", "http://127.0.0.1:8000/api/v1")


class TestDataIngestion:
    """Module 2 - Data ingestion test suite."""

    @pytest.fixture(autouse=True)
    def setup(self):
        self.base_url = BASE_URL
        yield

    # ---------------------------------------------------------------------
    # ING-001: Phishing single email ingestion
    # ---------------------------------------------------------------------
    def test_ing_001_phishing_single_email_ingestion(self):
        payload = {
            "content": "Urgent: Verify your account now at http://suspicious-example.com/login",
            "sender": "security@fake-bank.com",
            "subject": "Account Verification Required",
            "recipient": "user@company.com",
            "email_id": f"email_ing_{int(time.time())}",
        }

        response = requests.post(f"{self.base_url}/threats/scan", json=payload)
        assert response.status_code == 200, f"Expected 200, got {response.status_code}: {response.text}"

        data = response.json()
        assert data.get("success") is True
        assert "result" in data
        assert "pipeline_results" in data["result"]

    # ---------------------------------------------------------------------
    # ING-002: Phishing batch email ingestion
    # ---------------------------------------------------------------------
    def test_ing_002_phishing_batch_email_ingestion(self):
        payload = {
            "emails": [
                {
                    "content": "Invoice attached. Review immediately.",
                    "sender": "finance@vendor.com",
                    "subject": "Invoice #00921",
                    "recipient": "accounts@company.com",
                },
                {
                    "content": "Click this urgent verification link: http://urgent-reset.example.com",
                    "sender": "support@service-alert.com",
                    "subject": "Password Reset Required",
                    "recipient": "employee@company.com",
                },
            ]
        }

        response = requests.post(f"{self.base_url}/threats/scan/batch", json=payload)
        assert response.status_code == 200, f"Expected 200, got {response.status_code}: {response.text}"

        data = response.json()
        assert data.get("success") is True
        assert "summary" in data
        assert data["summary"].get("total_scanned") == 2
        assert len(data.get("results", [])) == 2

    # ---------------------------------------------------------------------
    # ING-003: Phishing ingestion validation (empty content)
    # ---------------------------------------------------------------------
    def test_ing_003_phishing_ingestion_validation_empty_content(self):
        payload = {"content": "", "sender": "a@b.com", "subject": "x"}

        response = requests.post(f"{self.base_url}/threats/scan/quick", json=payload)
        assert response.status_code == 422, f"Expected 422, got {response.status_code}: {response.text}"

    # ---------------------------------------------------------------------
    # ING-004: Ransomware command ingestion
    # ---------------------------------------------------------------------
    def test_ing_004_ransomware_command_ingestion(self):
        payload = {
            "command": "vssadmin delete shadows /all /quiet",
            "command_id": f"cmd_ing_{int(time.time())}",
            "source_host": "host-acds-01",
            "process_name": "powershell.exe",
            "user": "lab-user",
        }

        response = requests.post(f"{self.base_url}/ransomware/scan", json=payload)
        assert response.status_code == 200, f"Expected 200, got {response.status_code}: {response.text}"

        data = response.json()
        assert data.get("success") is True
        assert "result" in data
        assert "pipeline_results" in data["result"]

    # ---------------------------------------------------------------------
    # ING-005: Malware metadata ingestion
    # ---------------------------------------------------------------------
    def test_ing_005_malware_metadata_ingestion(self):
        payload = {
            "filename": "sample_payload.exe",
            "file_hash": "a1b2c3d4e5f6a7b8c9d0e1f2a3b4c5d6",
            "file_size": 245760,
            "file_type": "pe",
            "sample_id": f"sample_ing_{int(time.time())}",
        }

        response = requests.post(f"{self.base_url}/malware/scan", json=payload)
        assert response.status_code == 200, f"Expected 200, got {response.status_code}: {response.text}"

        data = response.json()
        assert data.get("success") is True
        assert "result" in data
        assert "pipeline_results" in data["result"]

    # ---------------------------------------------------------------------
    # ING-006: Malware batch ingestion
    # ---------------------------------------------------------------------
    def test_ing_006_malware_batch_ingestion(self):
        payload = {
            "samples": [
                {
                    "filename": "sample1.exe",
                    "file_hash": "11112222333344445555666677778888",
                    "file_size": 50000,
                    "file_type": "pe",
                },
                {
                    "filename": "sample2.dll",
                    "file_hash": "9999aaaabbbbccccddddeeeeffff0000",
                    "file_size": 98000,
                    "file_type": "dll",
                },
            ]
        }

        response = requests.post(f"{self.base_url}/malware/scan/batch", json=payload)
        assert response.status_code == 200, f"Expected 200, got {response.status_code}: {response.text}"

        data = response.json()
        assert data.get("success") is True
        assert "summary" in data
        assert data["summary"].get("total_scanned") == 2
        assert len(data.get("results", [])) == 2

    # ---------------------------------------------------------------------
    # ING-007: Credential stuffing login-event ingestion
    # ---------------------------------------------------------------------
    def test_ing_007_credential_login_event_ingestion(self):
        payload = {
            "username": "TestUser",
            "ip_address": "198.51.100.25",
            "success": False,
            "timestamp": datetime.now(timezone.utc).isoformat(),
            "user_agent": "ACDS-Test-Agent/1.0",
            "country": "US",
        }

        response = requests.post(f"{self.base_url}/credential-stuffing/login-event", json=payload)
        assert response.status_code == 200, f"Expected 200, got {response.status_code}: {response.text}"

        data = response.json()
        assert data.get("success") is True
        assert "event_id" in data
        assert "risk_score" in data
        assert "severity" in data

    # ---------------------------------------------------------------------
    # ING-008: Credential stuffing batch analyze ingestion
    # ---------------------------------------------------------------------
    def test_ing_008_credential_batch_analyze_ingestion(self):
        now = datetime.now(timezone.utc)
        payload = {
            "events": [
                {
                    "username": "user_01",
                    "ip_address": "203.0.113.10",
                    "success": False,
                    "timestamp": (now - timedelta(seconds=30)).isoformat(),
                    "user_agent": "BrowserA",
                    "country": "US",
                },
                {
                    "username": "user_02",
                    "ip_address": "203.0.113.10",
                    "success": False,
                    "timestamp": now.isoformat(),
                    "user_agent": "BrowserB",
                    "country": "US",
                },
            ]
        }

        response = requests.post(f"{self.base_url}/credential-stuffing/analyze", json=payload)
        assert response.status_code == 200, f"Expected 200, got {response.status_code}: {response.text}"

        data = response.json()
        assert data.get("success") is True
        assert data.get("count") == 2
        assert "results" in data
        assert len(data["results"]) == 2

    # ---------------------------------------------------------------------
    # ING-009: Credential ingestion validation (missing required fields)
    # ---------------------------------------------------------------------
    def test_ing_009_credential_ingestion_validation_missing_required(self):
        payload = {
            "username": "user_without_ip",
            "success": False,
        }

        response = requests.post(f"{self.base_url}/credential-stuffing/login-event", json=payload)
        assert response.status_code == 422, f"Expected 422, got {response.status_code}: {response.text}"

    # ---------------------------------------------------------------------
    # ING-010: Malware ingestion validation (short hash)
    # ---------------------------------------------------------------------
    def test_ing_010_malware_ingestion_validation_short_hash(self):
        payload = {
            "filename": "bad_sample.exe",
            "file_hash": "1234",  # too short (min_length=8)
            "file_size": 1000,
            "file_type": "pe",
        }

        response = requests.post(f"{self.base_url}/malware/scan", json=payload)
        assert response.status_code == 422, f"Expected 422, got {response.status_code}: {response.text}"


if __name__ == "__main__":
    pytest.main([__file__, "-v", "--tb=short"])

