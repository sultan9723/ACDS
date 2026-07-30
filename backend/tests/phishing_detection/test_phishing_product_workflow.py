"""Regression tests for the product Email Phishing workflow."""

import sys
from datetime import datetime, timezone
from pathlib import Path
from types import SimpleNamespace

import pytest

BACKEND_ROOT = Path(__file__).resolve().parents[2]
if str(BACKEND_ROOT) not in sys.path:
    sys.path.insert(0, str(BACKEND_ROOT))

from api.routes import dashboard as dashboard_routes
from api.routes import threats as threats_routes
from services.phishing_local_store import PhishingLocalStore
from services.phishing_repository import PhishingRepository
from services.phishing_review_service import PhishingReviewService
from services.phishing_test_run_service import PhishingTestRunBusyError, PhishingTestRunService


class StubDatasetLoader:
    def select_samples(self, count=2, include_legitimate=True, seed=None):
        return SimpleNamespace(
            samples=[
                {
                    "dataset_record_id": "row-phish-1",
                    "row_number": 1,
                    "source": "test_dataset",
                    "sender": "security-alert@example-payments.test",
                    "recipient": "victim@example.com",
                    "subject": "Verify your account now",
                    "content": "Please verify your account at http://bad.test/login",
                    "expected_label": "phishing",
                },
                {
                    "dataset_record_id": "row-safe-1",
                    "row_number": 2,
                    "source": "test_dataset",
                    "sender": "hr@example.com",
                    "recipient": "employee@example.com",
                    "subject": "Weekly schedule",
                    "content": "Your weekly schedule is attached.",
                    "expected_label": "legitimate",
                },
            ][:count],
            metadata={
                "source": "test_dataset",
                "total_records": 2,
                "selected_records": min(count, 2),
                "include_legitimate": include_legitimate,
                "seed": seed,
            },
        )

    def get_dataset_metadata(self):
        return {"source": "test_dataset", "total_records": 2}


class StubOrchestrator:
    def process_email(self, full_content, email_id):
        is_phishing = "verify your account" in full_content.lower()
        actions = ["quarantine_email", "block_sender"] if is_phishing else []
        severity = "HIGH" if is_phishing else "LOW"
        confidence = 0.94 if is_phishing else 0.08

        return {
            "incident_id": f"INC-{email_id}",
            "severity": severity,
            "risk_score": 94 if is_phishing else 8,
            "processing_time_ms": 12,
            "pipeline_results": {
                "detection": {
                    "is_phishing": is_phishing,
                    "confidence": confidence,
                    "severity": severity,
                    "risk_score": 94 if is_phishing else 8,
                    "risk_factors": ["credential_request"] if is_phishing else [],
                },
                "explainability": {
                    "explanation": "Credential request detected" if is_phishing else "No suspicious indicators",
                    "evidence": ["verify your account"] if is_phishing else [],
                    "iocs": {"urls": ["http://bad.test/login"]} if is_phishing else {},
                },
                "response": {
                    "actions_executed": actions,
                },
            },
        }


class StubReportGenerator:
    def generate_incident_report(self, threat_data, pipeline_results):
        return SimpleNamespace(report_id=f"RPT-{threat_data['threat_id']}")


@pytest.fixture
def isolated_repository(tmp_path, monkeypatch):
    store = PhishingLocalStore(str(tmp_path / "phishing_store.json"))

    import services.phishing_repository as repository_module

    monkeypatch.setattr(repository_module, "get_collection", None)
    monkeypatch.setattr(repository_module, "get_phishing_local_store", lambda: store)
    return PhishingRepository()


@pytest.fixture
def phishing_test_run_service(isolated_repository, monkeypatch):
    import services.phishing_test_run_service as test_run_module

    def lifecycle_trace(pipeline_result, is_phishing, actions_taken, report_id=None):
        return {
            "state": "reported" if report_id else ("resolved" if is_phishing else "scanned"),
            "report_status": "generated" if report_id else ("pending" if is_phishing else "not_required"),
            "actions": actions_taken,
            "response_summary": "Automated response executed" if actions_taken else "No response required",
            "response_details": {"action_count": len(actions_taken)},
            "stages": [],
        }

    monkeypatch.setattr(test_run_module, "get_phishing_repository", lambda: isolated_repository)
    monkeypatch.setattr(test_run_module, "get_phishing_dataset_loader", lambda: StubDatasetLoader())
    monkeypatch.setattr(test_run_module, "get_orchestrator_agent", lambda: StubOrchestrator())
    monkeypatch.setattr(test_run_module, "get_incident_report_generator", lambda: StubReportGenerator())
    monkeypatch.setattr(test_run_module, "build_phishing_lifecycle_trace", lifecycle_trace)
    return PhishingTestRunService()


def test_phishing_test_run_uses_dataset_and_persists_pipeline_artifacts(
    isolated_repository,
    phishing_test_run_service,
):
    result = phishing_test_run_service.run_test_batch(count=2, include_legitimate=True, seed=7)

    assert result["success"] is True
    assert result["status"] == "completed"
    assert result["summary"]["dataset_source"] == "test_dataset"
    assert result["summary"]["status"] == "completed"
    assert result["summary"]["duration_ms"] >= 0
    assert result["summary"]["total_scanned"] == 2
    assert result["summary"]["phishing_detected"] == 1
    assert result["summary"]["accuracy"] == 1.0
    assert all(item["pipeline_status"] == "completed" for item in result["results"])
    assert all(item["duration_ms"] >= 0 for item in result["results"])
    assert {item["sample_index"] for item in result["results"]} == {1, 2}

    scans = isolated_repository.list_scans(limit=10).records
    threats = isolated_repository.list_threats(limit=10).records
    logs = isolated_repository.list_activity_logs(limit=20).records

    assert len(scans) == 2
    assert len(threats) == 1
    assert {scan["data_source"] for scan in scans} == {"test_dataset"}
    assert {scan["expected_label"] for scan in scans} == {"phishing", "legitimate"}

    phishing_scan = next(scan for scan in scans if scan["is_phishing"])
    assert phishing_scan["threat_id"] == threats[0]["threat_id"]
    assert phishing_scan["report_id"] == threats[0]["report_id"]
    assert phishing_scan["lifecycle_state"] == "reported"
    assert phishing_scan["report_status"] == "generated"
    assert phishing_scan["pipeline_status"] == "completed"
    assert phishing_scan["sample_duration_ms"] >= 0

    events = {log["event"] for log in logs}
    assert {
        "phishing_test_run_started",
        "email_scanned",
        "threat_detected",
        "threat_resolved",
        "incident_report_generated",
        "phishing_test_run_completed",
    }.issubset(events)
    completed_log = next(log for log in logs if log["event"] == "phishing_test_run_completed")
    assert completed_log["run_status"] == "completed"
    assert completed_log["duration_ms"] >= 0

    status = phishing_test_run_service.get_operational_status()
    assert status["active_run"] is None
    assert status["last_run"]["session_id"] == result["session_id"]
    assert status["last_run"]["status"] == "completed"


def test_phishing_test_run_rejects_overlapping_runs(phishing_test_run_service):
    phishing_test_run_service._run_lock.acquire()
    phishing_test_run_service._active_run = {
        "session_id": "PHISH-RUNNING",
        "status": "running",
    }

    try:
        with pytest.raises(PhishingTestRunBusyError):
            phishing_test_run_service.run_test_batch(count=1)

        status = phishing_test_run_service.get_operational_status()
        assert status["active_run"]["session_id"] == "PHISH-RUNNING"
    finally:
        phishing_test_run_service._active_run = None
        phishing_test_run_service._run_lock.release()


@pytest.mark.asyncio
async def test_phishing_review_persists_and_remains_visible_in_module_and_dashboard(
    isolated_repository,
    monkeypatch,
):
    now = datetime.now(timezone.utc)
    isolated_repository.save_scan(
        {
            "scan_id": "SCAN-REVIEW-1",
            "email_subject": "Verify payout details",
            "email_sender": "finance-alert@example.test",
            "email_content": "Verify payout details immediately.",
            "is_phishing": True,
            "confidence": 91.5,
            "risk_level": "HIGH",
            "expected_label": "legitimate",
            "predicted_label": "phishing",
            "correct": False,
            "evaluation_outcome": "false_positive",
            "data_source": "test_dataset",
            "scanned_at": now,
        }
    )
    isolated_repository.save_threat(
        {
            "threat_id": "THR-REVIEW-1",
            "scan_id": "SCAN-REVIEW-1",
            "module": "phishing",
            "threat_type": "Phishing",
            "severity": "HIGH",
            "status": "resolved",
            "confidence": 91.5,
            "email_subject": "Verify payout details",
            "email_sender": "finance-alert@example.test",
            "expected_label": "legitimate",
            "predicted_label": "phishing",
            "correct": False,
            "evaluation_outcome": "false_positive",
            "detected_at": now,
        }
    )

    import services.phishing_review_service as review_module

    monkeypatch.setattr(review_module, "get_phishing_repository", lambda: isolated_repository)
    review_service = PhishingReviewService()

    queue = review_service.list_review_queue(limit=10)
    assert queue["items"][0]["scan_id"] == "SCAN-REVIEW-1"
    assert queue["items"][0]["review_status"] == "needs_review"
    assert queue["items"][0]["review_priority"] == 100

    review = review_service.submit_review(
        scan_id="SCAN-REVIEW-1",
        verdict="false_positive",
        analyst="qa-analyst",
        notes="Dataset label confirms this is legitimate.",
    )

    assert review["analyst_verdict"] == "false_positive"
    assert isolated_repository.get_scan("SCAN-REVIEW-1")["analyst_verdict"] == "false_positive"
    assert isolated_repository.get_threat("THR-REVIEW-1")["status"] == "false_positive"

    monkeypatch.setattr(threats_routes, "get_phishing_repository", lambda: isolated_repository)
    monkeypatch.setattr(dashboard_routes, "USE_DATABASE", False)
    monkeypatch.setattr(dashboard_routes, "get_collection", None)
    monkeypatch.setattr(dashboard_routes, "get_phishing_repository", lambda: isolated_repository)

    scan_response = await threats_routes.list_scanned_emails(limit=10)
    threat_response = await dashboard_routes.get_recent_threats(limit=10)
    activity_response = await dashboard_routes.get_activity_logs(limit=20)

    email = next(item for item in scan_response["emails"] if item["scan_id"] == "SCAN-REVIEW-1")
    threat = next(item for item in threat_response["threats"] if item["id"] == "THR-REVIEW-1")
    review_log = next(
        item for item in activity_response["logs"] if item["event"] == "analyst_review_submitted"
    )

    assert email["analyst_verdict"] == "false_positive"
    assert email["review_status"] == "reviewed"
    assert threat["analyst_verdict"] == "false_positive"
    assert threat["review_status"] == "reviewed"
    assert review_log["scan_id"] == "SCAN-REVIEW-1"
    assert review_log["details"]["analyst_verdict"] == "false_positive"


def test_invalid_phishing_review_verdict_does_not_mutate_scan(isolated_repository, monkeypatch):
    isolated_repository.save_scan(
        {
            "scan_id": "SCAN-VALIDATION-1",
            "email_subject": "Normal notice",
            "email_sender": "notice@example.test",
            "is_phishing": False,
            "confidence": 3.2,
            "scanned_at": datetime.now(timezone.utc),
        }
    )

    import services.phishing_review_service as review_module

    monkeypatch.setattr(review_module, "get_phishing_repository", lambda: isolated_repository)
    review_service = PhishingReviewService()

    with pytest.raises(ValueError):
        review_service.submit_review("SCAN-VALIDATION-1", "maybe_phishing")

    scan = isolated_repository.get_scan("SCAN-VALIDATION-1")
    assert "analyst_verdict" not in scan
    assert "review_status" not in scan
