"""
Phishing test-run service.

Provides a product-facing batch runner for the Email Phishing module. Unlike the
legacy dashboard demo and the lightweight testing API, this service sends every
sample through the full phishing pipeline and persists operational artifacts.
"""

import uuid
import logging
import threading
import time
from datetime import datetime, timezone
from typing import Any, Dict, List, Optional

try:
    from agents.orchestrator_agent import get_orchestrator_agent
    from services.incident_report_generator import get_incident_report_generator
    from services.phishing_dataset import DATASET_SOURCE, get_phishing_dataset_loader
    from services.phishing_evaluation import (
        evaluate_phishing_prediction,
        summarize_phishing_evaluations,
    )
    from services.phishing_lifecycle import build_phishing_lifecycle_trace
    from services.phishing_repository import get_phishing_repository
except ImportError:
    try:
        from backend.agents.orchestrator_agent import get_orchestrator_agent
        from backend.services.incident_report_generator import get_incident_report_generator
        from backend.services.phishing_dataset import DATASET_SOURCE, get_phishing_dataset_loader
        from backend.services.phishing_evaluation import (
            evaluate_phishing_prediction,
            summarize_phishing_evaluations,
        )
        from backend.services.phishing_lifecycle import build_phishing_lifecycle_trace
        from backend.services.phishing_repository import get_phishing_repository
    except ImportError:
        get_orchestrator_agent = None
        get_incident_report_generator = None
        DATASET_SOURCE = "phishing_test_dataset"
        get_phishing_dataset_loader = None
        evaluate_phishing_prediction = None
        summarize_phishing_evaluations = None
        build_phishing_lifecycle_trace = None
        get_phishing_repository = None


logger = logging.getLogger(__name__)


class PhishingTestRunBusyError(RuntimeError):
    """Raised when a phishing test run is already active in this process."""


class PhishingTestRunService:
    """Runs phishing module test batches through the full production pipeline."""

    def __init__(self) -> None:
        self.dataset_loader = get_phishing_dataset_loader() if get_phishing_dataset_loader else None
        self.repository = get_phishing_repository() if get_phishing_repository else None
        self._run_lock = threading.Lock()
        self._active_run: Optional[Dict[str, Any]] = None
        self._last_run: Optional[Dict[str, Any]] = None

    def run_test_batch(
        self,
        count: int = 5,
        include_legitimate: bool = True,
        seed: Optional[int] = None,
    ) -> Dict[str, Any]:
        if not self._run_lock.acquire(blocking=False):
            raise PhishingTestRunBusyError("A phishing test run is already in progress")

        if count < 1:
            self._run_lock.release()
            raise ValueError("count must be at least 1")
        if count > 50:
            self._run_lock.release()
            raise ValueError("count cannot exceed 50")
        if get_orchestrator_agent is None:
            self._run_lock.release()
            raise RuntimeError("Orchestrator service is not available")
        if self.dataset_loader is None:
            self._run_lock.release()
            raise RuntimeError("Phishing dataset loader is not available")

        session_id = f"PHISH-{uuid.uuid4().hex[:8].upper()}"
        started_at = datetime.now(timezone.utc)
        started_monotonic = time.monotonic()
        self._active_run = {
            "session_id": session_id,
            "status": "running",
            "started_at": started_at.isoformat(),
            "samples_requested": count,
            "include_legitimate": include_legitimate,
            "seed": seed,
        }

        try:
            dataset_selection = self.dataset_loader.select_samples(
                count=count,
                include_legitimate=include_legitimate,
                seed=seed,
            )
            samples = list(dataset_selection.samples or [])
            dataset_metadata = dataset_selection.metadata or {}
            if not samples:
                raise ValueError("No phishing dataset samples are available for this test run")

            results = []
            self._active_run.update(
                {
                    "samples_selected": len(samples),
                    "dataset_source": dataset_metadata.get("source", DATASET_SOURCE),
                }
            )

            self._log_activity(
                {
                    "event": "phishing_test_run_started",
                    "action_type": "test_run_started",
                    "module": "phishing",
                    "session_id": session_id,
                    "run_status": "running",
                    "samples_requested": count,
                    "samples_selected": len(samples),
                    "include_legitimate": include_legitimate,
                    "seed": seed,
                    "dataset": dataset_metadata,
                    "timestamp": started_at,
                }
            )

            sample_total = len(samples)
            for index, sample in enumerate(samples, start=1):
                results.append(self._process_sample(sample, session_id, index, sample_total))

            completed_at = datetime.now(timezone.utc)
            duration_ms = self._duration_ms(started_monotonic)
            phishing_detected = sum(1 for item in results if item.get("is_phishing"))
            failed = sum(1 for item in results if not item.get("success"))
            run_status = self._run_status(total=len(results), failed=failed)
            evaluation_summary = self._summarize_evaluation(results)

            summary = {
                "session_id": session_id,
                "status": run_status,
                "started_at": started_at.isoformat(),
                "completed_at": completed_at.isoformat(),
                "duration_ms": duration_ms,
                "total_scanned": len(results),
                "phishing_detected": phishing_detected,
                "safe_detected": len(results) - phishing_detected - failed,
                "failed": failed,
                "dataset_source": dataset_metadata.get("source", DATASET_SOURCE),
                "dataset": dataset_metadata,
                "evaluation": evaluation_summary,
                "accuracy": evaluation_summary.get("accuracy", 0),
                "precision": evaluation_summary.get("precision", 0),
                "recall": evaluation_summary.get("recall", 0),
                "f1_score": evaluation_summary.get("f1_score", 0),
                "confusion_matrix": evaluation_summary.get("confusion_matrix", {}),
                "persistence": {
                    "scans_stored": sum(1 for item in results if item.get("scan_id")),
                    "threats_stored": sum(1 for item in results if item.get("threat_id")),
                    "reports_generated": sum(1 for item in results if item.get("report_id")),
                },
            }

            self._log_activity(
                {
                    "event": "phishing_test_run_completed",
                    "action_type": "test_run_completed",
                    "module": "phishing",
                    "session_id": session_id,
                    "run_status": run_status,
                    "duration_ms": duration_ms,
                    "samples_processed": len(results),
                    "phishing_detected": phishing_detected,
                    "failed": failed,
                    "dataset": dataset_metadata,
                    "accuracy": evaluation_summary.get("accuracy"),
                    "precision": evaluation_summary.get("precision"),
                    "recall": evaluation_summary.get("recall"),
                    "f1_score": evaluation_summary.get("f1_score"),
                    "confusion_matrix": evaluation_summary.get("confusion_matrix", {}),
                    "timestamp": completed_at,
                }
            )

            response = {
                "success": run_status != "failed",
                "session_id": session_id,
                "status": run_status,
                "summary": summary,
                "results": results,
            }
            self._last_run = {
                "session_id": session_id,
                "status": run_status,
                "started_at": started_at.isoformat(),
                "completed_at": completed_at.isoformat(),
                "duration_ms": duration_ms,
                "samples_processed": len(results),
                "failed": failed,
            }
            return response
        except Exception as exc:
            failed_at = datetime.now(timezone.utc)
            duration_ms = self._duration_ms(started_monotonic)
            error_message = self._safe_error_message(exc)
            self._last_run = {
                "session_id": session_id,
                "status": "failed",
                "started_at": started_at.isoformat(),
                "completed_at": failed_at.isoformat(),
                "duration_ms": duration_ms,
                "error_type": exc.__class__.__name__,
                "error": error_message,
            }
            self._log_activity(
                {
                    "event": "phishing_test_run_failed",
                    "action_type": "test_run_failed",
                    "module": "phishing",
                    "session_id": session_id,
                    "run_status": "failed",
                    "duration_ms": duration_ms,
                    "error_type": exc.__class__.__name__,
                    "error": error_message,
                    "timestamp": failed_at,
                }
            )
            logger.exception("Phishing test run failed: %s", error_message)
            raise
        finally:
            self._active_run = None
            self._run_lock.release()

    def get_dataset_metadata(self) -> Dict[str, Any]:
        if self.dataset_loader is None:
            return {
                "source": "unavailable",
                "total_records": 0,
                "warnings": ["Phishing dataset loader is not available."],
            }
        return self.dataset_loader.get_dataset_metadata()

    def get_operational_status(self) -> Dict[str, Any]:
        return {
            "available": self.dataset_loader is not None and get_orchestrator_agent is not None,
            "repository_available": self.repository is not None,
            "dataset_available": self.dataset_loader is not None,
            "orchestrator_available": get_orchestrator_agent is not None,
            "active_run": self._active_run,
            "last_run": self._last_run,
        }

    def _process_sample(
        self,
        sample: Dict[str, Any],
        session_id: str,
        sample_index: int,
        sample_total: int,
    ) -> Dict[str, Any]:
        email_id = f"{session_id}-{sample_index:03d}"
        full_content = self._build_email_content(sample)
        sample_started_at = datetime.now(timezone.utc)
        sample_started_monotonic = time.monotonic()

        try:
            orchestrator = get_orchestrator_agent()
            pipeline_result = orchestrator.process_email(full_content, email_id)
            sample_completed_at = datetime.now(timezone.utc)
            sample_duration_ms = self._duration_ms(sample_started_monotonic)
            detection = pipeline_result.get("pipeline_results", {}).get("detection", {})
            explainability = pipeline_result.get("pipeline_results", {}).get("explainability", {})
            response = pipeline_result.get("pipeline_results", {}).get("response", {})

            is_phishing = bool(detection.get("is_phishing", False))
            confidence = self._confidence_percent(detection.get("confidence", 0))
            severity = pipeline_result.get("severity", detection.get("severity", "LOW"))
            actions_taken = response.get("actions_executed", []) or []
            evaluation = self._evaluate_sample(
                expected_label=sample.get("expected_label"),
                predicted_is_phishing=is_phishing,
                confidence=confidence,
            )
            lifecycle_trace = self._build_lifecycle_trace(
                pipeline_result=pipeline_result,
                is_phishing=is_phishing,
                actions_taken=actions_taken,
            )

            scan_id = self._store_email_scan(
                sample=sample,
                session_id=session_id,
                email_id=email_id,
                sample_index=sample_index,
                sample_total=sample_total,
                pipeline_result=pipeline_result,
                is_phishing=is_phishing,
                confidence=confidence,
                severity=severity,
                lifecycle_trace=lifecycle_trace,
                evaluation=evaluation,
                sample_started_at=sample_started_at,
                sample_completed_at=sample_completed_at,
                sample_duration_ms=sample_duration_ms,
            )

            threat_id = None
            report_id = None
            if is_phishing:
                threat_id = self._store_threat(
                    sample=sample,
                    session_id=session_id,
                    scan_id=scan_id,
                    sample_index=sample_index,
                    sample_total=sample_total,
                    pipeline_result=pipeline_result,
                    confidence=confidence,
                    severity=severity,
                    actions_taken=actions_taken,
                    lifecycle_trace=lifecycle_trace,
                    evaluation=evaluation,
                )
                report_id = self._generate_report(
                    sample=sample,
                    threat_id=threat_id or pipeline_result.get("incident_id"),
                    pipeline_result=pipeline_result,
                    confidence=confidence,
                    severity=severity,
                    actions_taken=actions_taken,
                )
                lifecycle_trace = self._build_lifecycle_trace(
                    pipeline_result=pipeline_result,
                    is_phishing=is_phishing,
                    actions_taken=actions_taken,
                    report_id=report_id,
                )
                self._attach_detection_artifacts(
                    scan_id,
                    threat_id,
                    report_id,
                    lifecycle_trace=lifecycle_trace,
                )

            self._write_sample_logs(
                sample=sample,
                session_id=session_id,
                scan_id=scan_id,
                threat_id=threat_id,
                sample_index=sample_index,
                sample_total=sample_total,
                is_phishing=is_phishing,
                confidence=confidence,
                severity=severity,
                actions_taken=actions_taken,
                lifecycle_trace=lifecycle_trace,
                report_id=report_id,
                evaluation=evaluation,
                sample_duration_ms=sample_duration_ms,
            )

            return {
                "success": True,
                "pipeline_status": "completed",
                "sample_id": email_id,
                "sample_index": sample_index,
                "sample_total": sample_total,
                "scan_id": scan_id,
                "threat_id": threat_id,
                "incident_id": pipeline_result.get("incident_id"),
                "report_id": report_id,
                "sender": sample.get("sender"),
                "subject": sample.get("subject"),
                "dataset_record_id": sample.get("dataset_record_id"),
                "data_source": sample.get("source", DATASET_SOURCE),
                "dataset_row_number": sample.get("row_number"),
                "expected_label": sample.get("expected_label"),
                "predicted_label": evaluation.get("predicted_label"),
                "expected_is_phishing": evaluation.get("expected_is_phishing"),
                "correct": evaluation.get("correct"),
                "evaluation_outcome": evaluation.get("outcome"),
                "evaluation": evaluation,
                "is_phishing": is_phishing,
                "confidence": confidence,
                "severity": severity,
                "started_at": sample_started_at.isoformat(),
                "completed_at": sample_completed_at.isoformat(),
                "duration_ms": sample_duration_ms,
                "actions_taken": actions_taken,
                "lifecycle_state": lifecycle_trace.get("state"),
                "lifecycle_trace": lifecycle_trace,
                "response_summary": lifecycle_trace.get("response_summary"),
                "explanation": explainability.get("explanation"),
                "evidence": explainability.get("evidence", []),
                "pipeline_results": pipeline_result.get("pipeline_results", {}),
            }
        except Exception as exc:
            self._log_activity(
                {
                    "event": "phishing_test_sample_failed",
                    "action_type": "sample_failed",
                    "module": "phishing",
                    "session_id": session_id,
                    "sample_id": email_id,
                    "sample_index": sample_index,
                    "sample_total": sample_total,
                    "run_status": "sample_failed",
                    "duration_ms": self._duration_ms(sample_started_monotonic),
                    "email_subject": sample.get("subject"),
                    "sender": sample.get("sender"),
                    "error_type": exc.__class__.__name__,
                    "error": self._safe_error_message(exc),
                    "timestamp": datetime.now(timezone.utc),
                }
            )
            return {
                "success": False,
                "pipeline_status": "failed",
                "sample_id": email_id,
                "sample_index": sample_index,
                "sample_total": sample_total,
                "sender": sample.get("sender"),
                "subject": sample.get("subject"),
                "expected_label": sample.get("expected_label"),
                "error_type": exc.__class__.__name__,
                "error": self._safe_error_message(exc),
            }

    def _build_email_content(self, sample: Dict[str, Any]) -> str:
        return (
            f"From: {sample.get('sender', 'unknown')}\n"
            f"Subject: {sample.get('subject', 'No Subject')}\n\n"
            f"{sample.get('content', '')}"
        )

    def _store_email_scan(
        self,
        sample: Dict[str, Any],
        session_id: str,
        email_id: str,
        sample_index: int,
        sample_total: int,
        pipeline_result: Dict[str, Any],
        is_phishing: bool,
        confidence: float,
        severity: str,
        lifecycle_trace: Dict[str, Any],
        evaluation: Dict[str, Any],
        sample_started_at: datetime,
        sample_completed_at: datetime,
        sample_duration_ms: int,
    ) -> Optional[str]:
        scan_id = f"SCAN-{uuid.uuid4().hex[:8].upper()}"
        explainability = pipeline_result.get("pipeline_results", {}).get("explainability", {})
        scan_doc = {
            "scan_id": scan_id,
            "email_id": email_id,
            "session_id": session_id,
            "sample_index": sample_index,
            "sample_total": sample_total,
            "module": "phishing",
            "email_subject": sample.get("subject", "No Subject"),
            "email_sender": sample.get("sender", "Unknown"),
            "email_recipient": sample.get("recipient"),
            "email_content": sample.get("content", "")[:500],
            "is_phishing": is_phishing,
            "confidence": confidence,
            "risk_level": severity if is_phishing else "SAFE",
            "indicators": explainability.get("iocs", {}),
            "evidence": explainability.get("evidence", []),
            "data_source": sample.get("source", DATASET_SOURCE),
            "expected_label": sample.get("expected_label"),
            "predicted_label": evaluation.get("predicted_label"),
            "expected_is_phishing": evaluation.get("expected_is_phishing"),
            "predicted_is_phishing": evaluation.get("predicted_is_phishing"),
            "correct": evaluation.get("correct"),
            "evaluation_outcome": evaluation.get("outcome"),
            "evaluation": evaluation,
            "incident_id": pipeline_result.get("incident_id"),
            "lifecycle_state": lifecycle_trace.get("state"),
            "lifecycle_trace": lifecycle_trace,
            "response_actions": lifecycle_trace.get("actions", []),
            "response_summary": lifecycle_trace.get("response_summary"),
            "response_details": lifecycle_trace.get("response_details", {}),
            "report_status": lifecycle_trace.get("report_status"),
            "processing_time_ms": pipeline_result.get("processing_time_ms", 0),
            "sample_duration_ms": sample_duration_ms,
            "pipeline_status": "completed",
            "model_version": "2.0.0",
            "started_at": sample_started_at,
            "completed_at": sample_completed_at,
            "scanned_at": sample_completed_at,
        }
        if self.repository:
            self.repository.save_scan(scan_doc)
        return scan_id

    def _store_threat(
        self,
        sample: Dict[str, Any],
        session_id: str,
        scan_id: Optional[str],
        sample_index: int,
        sample_total: int,
        pipeline_result: Dict[str, Any],
        confidence: float,
        severity: str,
        actions_taken: List[str],
        lifecycle_trace: Dict[str, Any],
        evaluation: Dict[str, Any],
    ) -> Optional[str]:
        threat_id = f"THR-{uuid.uuid4().hex[:8].upper()}"
        detection = pipeline_result.get("pipeline_results", {}).get("detection", {})
        explainability = pipeline_result.get("pipeline_results", {}).get("explainability", {})
        now = datetime.now(timezone.utc)
        threat_doc = {
            "threat_id": threat_id,
            "incident_id": pipeline_result.get("incident_id"),
            "scan_id": scan_id,
            "session_id": session_id,
            "sample_index": sample_index,
            "sample_total": sample_total,
            "module": "phishing",
            "threat_type": "Phishing",
            "type": "Phishing",
            "severity": severity,
            "status": "resolved" if actions_taken else "active",
            "confidence": confidence,
            "risk_score": pipeline_result.get("risk_score", detection.get("risk_score", 0)),
            "email_subject": sample.get("subject", "No Subject"),
            "email_sender": sample.get("sender", "Unknown"),
            "email_recipient": sample.get("recipient"),
            "email_content_preview": sample.get("content", "")[:200],
            "indicators": explainability.get("iocs", {}),
            "evidence": explainability.get("evidence", []),
            "risk_factors": detection.get("risk_factors", []),
            "actions_taken": actions_taken,
            "action_taken": actions_taken[0] if actions_taken else None,
            "response_actions": lifecycle_trace.get("actions", []),
            "response_summary": lifecycle_trace.get("response_summary"),
            "response_details": lifecycle_trace.get("response_details", {}),
            "lifecycle_state": lifecycle_trace.get("state"),
            "lifecycle_trace": lifecycle_trace,
            "report_status": lifecycle_trace.get("report_status"),
            "pipeline_status": "completed",
            "detected_at": now,
            "updated_at": now,
            "resolved_at": now if actions_taken else None,
            "data_source": sample.get("source", DATASET_SOURCE),
            "expected_label": sample.get("expected_label"),
            "predicted_label": evaluation.get("predicted_label"),
            "expected_is_phishing": evaluation.get("expected_is_phishing"),
            "predicted_is_phishing": evaluation.get("predicted_is_phishing"),
            "correct": evaluation.get("correct"),
            "evaluation_outcome": evaluation.get("outcome"),
            "evaluation": evaluation,
        }
        if self.repository:
            self.repository.save_threat(threat_doc)
        return threat_id

    def _generate_report(
        self,
        sample: Dict[str, Any],
        threat_id: Optional[str],
        pipeline_result: Dict[str, Any],
        confidence: float,
        severity: str,
        actions_taken: List[str],
    ) -> Optional[str]:
        if get_incident_report_generator is None:
            return None

        try:
            report_generator = get_incident_report_generator()
            report = report_generator.generate_incident_report(
                threat_data={
                    "threat_id": threat_id,
                    "type": "Phishing",
                    "severity": severity,
                    "confidence": confidence,
                    "email_subject": sample.get("subject", "No Subject"),
                    "email_sender": sample.get("sender", "Unknown"),
                    "email_preview": sample.get("content", "")[:500],
                    "status": "resolved" if actions_taken else "active",
                    "actions_taken": actions_taken,
                },
                pipeline_results=pipeline_result.get("pipeline_results", {}),
            )
            return report.report_id if report else None
        except Exception as exc:
            print(f"Warning: Incident report generation failed: {exc}")
            return None

    def _attach_detection_artifacts(
        self,
        scan_id: Optional[str],
        threat_id: Optional[str],
        report_id: Optional[str],
        lifecycle_trace: Optional[Dict[str, Any]] = None,
    ) -> None:
        updates = {}
        if threat_id:
            updates["threat_id"] = threat_id
        if report_id:
            updates["report_id"] = report_id
        if lifecycle_trace:
            updates.update(self._lifecycle_update_fields(lifecycle_trace))

        if not updates:
            return

        if scan_id:
            if self.repository:
                self.repository.update_scan(scan_id, updates)

        if threat_id and report_id:
            if self.repository:
                self.repository.update_threat(threat_id, updates)

    def _write_sample_logs(
        self,
        sample: Dict[str, Any],
        session_id: str,
        scan_id: Optional[str],
        threat_id: Optional[str],
        sample_index: int,
        sample_total: int,
        is_phishing: bool,
        confidence: float,
        severity: str,
        actions_taken: List[str],
        lifecycle_trace: Dict[str, Any],
        report_id: Optional[str],
        evaluation: Dict[str, Any],
        sample_duration_ms: int,
    ) -> None:
        self._log_activity(
            {
                "event": "email_scanned",
                "action_type": "email_processed",
                "module": "phishing",
                "session_id": session_id,
                "scan_id": scan_id,
                "sample_index": sample_index,
                "sample_total": sample_total,
                "pipeline_status": "completed",
                "duration_ms": sample_duration_ms,
                "email_subject": sample.get("subject", "No Subject"),
                "sender": sample.get("sender", "Unknown"),
                "is_phishing": is_phishing,
                "is_threat": is_phishing,
                "confidence": confidence,
                "severity": severity,
                "lifecycle_state": lifecycle_trace.get("state"),
                "report_status": lifecycle_trace.get("report_status"),
                "expected": sample.get("expected_label"),
                "expected_label": evaluation.get("expected_label"),
                "predicted_label": evaluation.get("predicted_label"),
                "correct": evaluation.get("correct"),
                "evaluation_outcome": evaluation.get("outcome"),
                "data_source": sample.get("source", "builtin"),
                "timestamp": datetime.now(timezone.utc),
            }
        )

        if not is_phishing:
            return

        self._log_activity(
            {
                "event": "threat_detected",
                "action_type": "threat_detected",
                "module": "phishing",
                "session_id": session_id,
                "scan_id": scan_id,
                "threat_id": threat_id,
                "sample_index": sample_index,
                "sample_total": sample_total,
                "pipeline_status": "completed",
                "duration_ms": sample_duration_ms,
                "email_subject": sample.get("subject", "No Subject"),
                "sender": sample.get("sender", "Unknown"),
                "is_phishing": True,
                "is_threat": True,
                "confidence": confidence,
                "severity": severity,
                "actions": actions_taken,
                "lifecycle_state": lifecycle_trace.get("state"),
                "report_status": lifecycle_trace.get("report_status"),
                "expected_label": evaluation.get("expected_label"),
                "predicted_label": evaluation.get("predicted_label"),
                "correct": evaluation.get("correct"),
                "evaluation_outcome": evaluation.get("outcome"),
                "timestamp": datetime.now(timezone.utc),
            }
        )

        if actions_taken:
            self._log_activity(
                {
                    "event": "threat_resolved",
                    "action_type": "threat_resolved",
                    "module": "phishing",
                    "session_id": session_id,
                    "scan_id": scan_id,
                    "threat_id": threat_id,
                    "sample_index": sample_index,
                    "sample_total": sample_total,
                    "pipeline_status": "completed",
                    "duration_ms": sample_duration_ms,
                    "email_subject": sample.get("subject", "No Subject"),
                    "sender": sample.get("sender", "Unknown"),
                    "is_phishing": True,
                    "is_threat": True,
                    "confidence": confidence,
                    "severity": severity,
                    "resolution": "automated_response",
                    "actions": actions_taken,
                    "lifecycle_state": lifecycle_trace.get("state"),
                    "report_status": lifecycle_trace.get("report_status"),
                    "report_id": report_id,
                    "expected_label": evaluation.get("expected_label"),
                    "predicted_label": evaluation.get("predicted_label"),
                    "correct": evaluation.get("correct"),
                    "evaluation_outcome": evaluation.get("outcome"),
                    "timestamp": datetime.now(timezone.utc),
                }
            )

        if report_id:
            self._log_activity(
                {
                    "event": "incident_report_generated",
                    "action_type": "report_generated",
                    "module": "phishing",
                    "session_id": session_id,
                    "scan_id": scan_id,
                    "threat_id": threat_id,
                    "report_id": report_id,
                    "sample_index": sample_index,
                    "sample_total": sample_total,
                    "pipeline_status": "completed",
                    "duration_ms": sample_duration_ms,
                    "email_subject": sample.get("subject", "No Subject"),
                    "sender": sample.get("sender", "Unknown"),
                    "is_phishing": True,
                    "is_threat": True,
                    "confidence": confidence,
                    "severity": severity,
                    "lifecycle_state": lifecycle_trace.get("state"),
                    "report_status": lifecycle_trace.get("report_status"),
                    "expected_label": evaluation.get("expected_label"),
                    "predicted_label": evaluation.get("predicted_label"),
                    "correct": evaluation.get("correct"),
                    "evaluation_outcome": evaluation.get("outcome"),
                    "timestamp": datetime.now(timezone.utc),
                }
            )

    def _log_activity(self, log_data: Dict[str, Any]) -> None:
        log_data.setdefault("id", f"ACT-{uuid.uuid4().hex[:12].upper()}")
        log_data.setdefault("timestamp", datetime.now(timezone.utc))
        log_data["created_at"] = datetime.now(timezone.utc)
        if self.repository:
            self.repository.save_activity_log(log_data)

    def _build_lifecycle_trace(
        self,
        pipeline_result: Dict[str, Any],
        is_phishing: bool,
        actions_taken: List[str],
        report_id: Optional[str] = None,
    ) -> Dict[str, Any]:
        if build_phishing_lifecycle_trace is None:
            return {
                "state": pipeline_result.get("lifecycle_state", "reported" if report_id else "resolved"),
                "report_status": "generated" if report_id else ("pending" if is_phishing else "not_required"),
                "actions": actions_taken,
                "response_summary": "Lifecycle helper unavailable",
                "response_details": {},
                "stages": [],
            }
        return build_phishing_lifecycle_trace(
            pipeline_result,
            is_phishing=is_phishing,
            actions_taken=actions_taken,
            report_id=report_id,
        )

    def _lifecycle_update_fields(self, lifecycle_trace: Dict[str, Any]) -> Dict[str, Any]:
        return {
            "lifecycle_state": lifecycle_trace.get("state"),
            "lifecycle_trace": lifecycle_trace,
            "response_actions": lifecycle_trace.get("actions", []),
            "response_summary": lifecycle_trace.get("response_summary"),
            "response_details": lifecycle_trace.get("response_details", {}),
            "report_status": lifecycle_trace.get("report_status"),
        }

    def _evaluate_sample(
        self,
        expected_label: Optional[str],
        predicted_is_phishing: bool,
        confidence: float,
    ) -> Dict[str, Any]:
        if evaluate_phishing_prediction is None:
            expected = str(expected_label or "legitimate").lower()
            expected_is_phishing = expected == "phishing"
            return {
                "expected_label": expected,
                "expected_is_phishing": expected_is_phishing,
                "predicted_label": "phishing" if predicted_is_phishing else "legitimate",
                "predicted_is_phishing": predicted_is_phishing,
                "correct": expected_is_phishing == predicted_is_phishing,
                "outcome": "unknown",
                "confidence": confidence,
            }
        return evaluate_phishing_prediction(expected_label, predicted_is_phishing, confidence)

    def _summarize_evaluation(self, results: List[Dict[str, Any]]) -> Dict[str, Any]:
        if summarize_phishing_evaluations is None:
            return {
                "total_evaluated": 0,
                "failed": sum(1 for item in results if not item.get("success")),
                "accuracy": 0,
                "precision": 0,
                "recall": 0,
                "f1_score": 0,
                "confusion_matrix": {},
                "misclassifications": [],
            }
        return summarize_phishing_evaluations(results)

    def _confidence_percent(self, value: Any) -> float:
        try:
            confidence = float(value or 0)
        except (TypeError, ValueError):
            confidence = 0.0
        if confidence <= 1:
            confidence *= 100
        return round(confidence, 1)

    def _duration_ms(self, started_monotonic: float) -> int:
        return max(0, int((time.monotonic() - started_monotonic) * 1000))

    def _run_status(self, total: int, failed: int) -> str:
        if total <= 0:
            return "failed"
        if failed == 0:
            return "completed"
        if failed >= total:
            return "failed"
        return "partial_failure"

    def _safe_error_message(self, exc: Exception) -> str:
        message = str(exc) or exc.__class__.__name__
        return message[:500]


_service_instance: Optional[PhishingTestRunService] = None


def get_phishing_test_run_service() -> PhishingTestRunService:
    global _service_instance
    if _service_instance is None:
        _service_instance = PhishingTestRunService()
    return _service_instance
