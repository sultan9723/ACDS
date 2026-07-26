"""
ACDS Test Cases - Ransomware Detection Module
============================================
Python test cases for Module 4 (Ransomware Detection).

Scope:
- Full orchestrated scan
- Batch / quick / explain scan modes
- Three-layer and encryption-monitor paths
- Health, stats, model, and layer-status endpoints
- Basic validation checks
"""

import os
import time

import pytest
import requests


BASE_URL = os.getenv("ACDS_API_BASE_URL", "http://127.0.0.1:8000/api/v1")


class TestRansomwareDetection:
    """Module 4 - ransomware detection test suite."""

    @pytest.fixture(autouse=True)
    def setup(self):
        self.base_url = BASE_URL
        yield

    # ---------------------------------------------------------------------
    # RANS-001: Full orchestrator ransomware scan
    # ---------------------------------------------------------------------
    def test_rans_001_full_scan(self):
        payload = {
            "command": "vssadmin delete shadows /all /quiet",
            "command_id": f"rans_full_{int(time.time())}",
            "source_host": "soc-host-01",
            "process_name": "powershell.exe",
            "user": "test-user",
        }

        response = requests.post(f"{self.base_url}/ransomware/scan", json=payload)
        assert response.status_code == 200, f"Expected 200, got {response.status_code}: {response.text}"

        data = response.json()
        assert data.get("success") is True
        assert "result" in data
        assert "pipeline_results" in data["result"]

    # ---------------------------------------------------------------------
    # RANS-002: Batch scan ingestion and summary
    # ---------------------------------------------------------------------
    def test_rans_002_batch_scan(self):
        payload = {
            "commands": [
                {"command": "vssadmin delete shadows /all /quiet", "source_host": "host-a"},
                {"command": "notepad.exe C:\\notes.txt", "source_host": "host-b"},
            ]
        }

        response = requests.post(f"{self.base_url}/ransomware/scan/batch", json=payload)
        assert response.status_code == 200, f"Expected 200, got {response.status_code}: {response.text}"

        data = response.json()
        assert data.get("success") is True
        assert data.get("summary", {}).get("total_scanned") == 2
        assert len(data.get("results", [])) == 2

    # ---------------------------------------------------------------------
    # RANS-003: Quick scan endpoint
    # ---------------------------------------------------------------------
    def test_rans_003_quick_scan(self):
        payload = {"command": "bcdedit /set {default} recoveryenabled No"}

        response = requests.post(f"{self.base_url}/ransomware/scan/quick", json=payload)
        assert response.status_code == 200, f"Expected 200, got {response.status_code}: {response.text}"

        data = response.json()
        assert data.get("success") is True
        result = data.get("result", {})
        assert "is_ransomware" in result
        assert "confidence" in result
        assert "severity" in result

    # ---------------------------------------------------------------------
    # RANS-004: Scan with explainability
    # ---------------------------------------------------------------------
    def test_rans_004_scan_with_explainability(self):
        payload = {
            "command": "powershell -enc SQBFAFgAIAAoAE4AZQB3AC0ATwBiAGoAZQBjAHQA",
            "command_id": f"rans_explain_{int(time.time())}",
        }

        response = requests.post(f"{self.base_url}/ransomware/scan/explain", json=payload)
        assert response.status_code == 200, f"Expected 200, got {response.status_code}: {response.text}"

        data = response.json()
        assert data.get("success") is True
        assert "detection" in data
        assert "explainability" in data

    # ---------------------------------------------------------------------
    # RANS-005: List ransomware threats endpoint
    # ---------------------------------------------------------------------
    def test_rans_005_list_threats(self):
        response = requests.get(f"{self.base_url}/ransomware/list", params={"limit": 5})
        assert response.status_code == 200, f"Expected 200, got {response.status_code}: {response.text}"

        data = response.json()
        assert data.get("success") is True
        assert "threats" in data
        assert isinstance(data.get("threats"), list)

    # ---------------------------------------------------------------------
    # RANS-006: List ransomware scans endpoint
    # ---------------------------------------------------------------------
    def test_rans_006_list_scans(self):
        response = requests.get(f"{self.base_url}/ransomware/scans/list", params={"limit": 5})
        assert response.status_code == 200, f"Expected 200, got {response.status_code}: {response.text}"

        data = response.json()
        assert data.get("success") is True
        assert "scans" in data
        assert isinstance(data.get("scans"), list)

    # ---------------------------------------------------------------------
    # RANS-007: Module stats endpoint
    # ---------------------------------------------------------------------
    def test_rans_007_stats_endpoint(self):
        response = requests.get(f"{self.base_url}/ransomware/stats")
        assert response.status_code == 200, f"Expected 200, got {response.status_code}: {response.text}"

        data = response.json()
        assert data.get("success") is True
        assert "stats" in data

    # ---------------------------------------------------------------------
    # RANS-008: Model info endpoint
    # ---------------------------------------------------------------------
    def test_rans_008_model_info_endpoint(self):
        response = requests.get(f"{self.base_url}/ransomware/model/info")
        assert response.status_code == 200, f"Expected 200, got {response.status_code}: {response.text}"

        data = response.json()
        assert data.get("success") is True

    # ---------------------------------------------------------------------
    # RANS-009: Health endpoint
    # ---------------------------------------------------------------------
    def test_rans_009_health_endpoint(self):
        response = requests.get(f"{self.base_url}/ransomware/health")
        assert response.status_code == 200, f"Expected 200, got {response.status_code}: {response.text}"

        data = response.json()
        assert "success" in data

    # ---------------------------------------------------------------------
    # RANS-010: Detection layers status endpoint
    # ---------------------------------------------------------------------
    def test_rans_010_layers_status(self):
        response = requests.get(f"{self.base_url}/ransomware/layers/status")
        assert response.status_code == 200, f"Expected 200, got {response.status_code}: {response.text}"

        data = response.json()
        assert data.get("success") is True
        assert "status" in data

    # ---------------------------------------------------------------------
    # RANS-011: Three-layer detection (command-only path)
    # ---------------------------------------------------------------------
    def test_rans_011_detect_layers_command_only(self):
        payload = {
            "command": "wmic shadowcopy delete",
            "process_name": "cmd.exe",
            "source_host": "acds-lab-01",
            "user": "lab-admin",
        }

        response = requests.post(f"{self.base_url}/ransomware/detect-layers", json=payload)
        assert response.status_code == 200, f"Expected 200, got {response.status_code}: {response.text}"

        data = response.json()
        assert data.get("success") is True

    # ---------------------------------------------------------------------
    # RANS-012: Monitor encryption behavior endpoint
    # ---------------------------------------------------------------------
    def test_rans_012_monitor_encryption(self):
        payload = [
            {
                "path": "C:/data/docs/a.txt",
                "operation": "modify",
                "extension": ".txt",
                "process_pid": 4242,
                "process_name": "unknown.exe",
                "source_host": "host-01",
            },
            {
                "path": "C:/data/docs/b.txt",
                "operation": "rename",
                "extension": ".locked",
                "process_pid": 4242,
                "process_name": "unknown.exe",
                "source_host": "host-01",
            },
        ]

        response = requests.post(f"{self.base_url}/ransomware/monitor-encryption", json=payload)
        assert response.status_code == 200, f"Expected 200, got {response.status_code}: {response.text}"

        data = response.json()
        assert data.get("success") is True

    # ---------------------------------------------------------------------
    # RANS-013: Required-field validation (missing command)
    # ---------------------------------------------------------------------
    def test_rans_013_scan_validation_missing_command(self):
        payload = {
            "command_id": "missing-command",
            "source_host": "host-x",
        }

        response = requests.post(f"{self.base_url}/ransomware/scan", json=payload)
        assert response.status_code == 422, f"Expected 422, got {response.status_code}: {response.text}"


if __name__ == "__main__":
    pytest.main([__file__, "-v", "--tb=short"])

