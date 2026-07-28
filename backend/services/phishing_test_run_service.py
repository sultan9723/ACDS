"""
Phishing test-run service.

Provides a product-facing batch runner for the Email Phishing module. Unlike the
legacy dashboard demo and the lightweight testing API, this service sends every
sample through the full phishing pipeline and persists operational artifacts.
"""

import random
import uuid
from datetime import datetime, timezone
from typing import Any, Dict, List, Optional

try:
    from agents.orchestrator_agent import get_orchestrator_agent
    from services.incident_report_generator import get_incident_report_generator
    from services.phishing_repository import get_phishing_repository
except ImportError:
    try:
        from backend.agents.orchestrator_agent import get_orchestrator_agent
        from backend.services.incident_report_generator import get_incident_report_generator
        from backend.services.phishing_repository import get_phishing_repository
    except ImportError:
        get_orchestrator_agent = None
        get_incident_report_generator = None
        get_phishing_repository = None


PHISHING_TEST_DATASET = {
    "phishing": [
        {
            "subject": "URGENT: Verify your account today",
            "sender": "security-alert@bankofamerica-verify.com",
            "content": (
                "Dear customer, suspicious activity was detected on your account. "
                "Verify your identity immediately at http://secure-bankofamerica-login.com/verify "
                "or your account will be suspended within 24 hours."
            ),
        },
        {
            "subject": "Microsoft 365 password expiration notice",
            "sender": "admin@microsoft365-support.net",
            "content": (
                "Your Microsoft 365 password will expire in 2 hours. Update your password now "
                "at http://microsoft365-update.com/password to avoid service interruption."
            ),
        },
        {
            "subject": "PayPal account limited",
            "sender": "service@paypa1-secure.com",
            "content": (
                "We noticed unusual login activity on your PayPal account. Confirm your information "
                "at http://paypal-verify.xyz/confirm within 48 hours to restore access."
            ),
        },
        {
            "subject": "Invoice payment required immediately",
            "sender": "billing@quickbooks-invoices.com",
            "content": (
                "Invoice INV-2026-8847 is overdue. Pay now at "
                "http://quickbooks-pay-secure.com/invoice/INV-2026-8847 to avoid collections."
            ),
        },
        {
            "subject": "Apple ID locked after unusual sign-in",
            "sender": "appleid@apple-support-verify.com",
            "content": (
                "Your Apple ID was locked after a sign-in attempt from an unknown device. "
                "Verify now at http://appleid-verify-support.com/unlock or access may be disabled."
            ),
        },
    ],
    "legitimate": [
        {
            "subject": "Weekly project update",
            "sender": "manager@company.com",
            "content": (
                "Hi team, here is the weekly project update. We completed the API review, "
                "updated the timeline, and will meet tomorrow to discuss next steps."
            ),
        },
        {
            "subject": "Meeting notes from today's call",
            "sender": "colleague@company.com",
            "content": (
                "Thanks for joining today. Action items are attached in the shared workspace. "
                "Please add comments before Friday's planning session."
            ),
        },
        {
            "subject": "Your Amazon.com order has shipped",
            "sender": "ship-confirm@amazon.com",
            "content": (
                "Your order has shipped. You can track it from your Amazon account order history. "
                "Estimated delivery is listed in your account."
            ),
        },
    ],
}

DATASET_SOURCE = "phishing_test_dataset"


class PhishingTestRunService:
    """Runs phishing module test batches through the full production pipeline."""

    def __init__(self) -> None:
        self.dataset = PHISHING_TEST_DATASET
        self.repository = get_phishing_repository() if get_phishing_repository else None

    def run_test_batch(self, count: int = 5, include_legitimate: bool = True) -> Dict[str, Any]:
        if count < 1:
            raise ValueError("count must be at least 1")
        if count > 50:
            raise ValueError("count cannot exceed 50")
        if get_orchestrator_agent is None:
            raise RuntimeError("Orchestrator service is not available")

        session_id = f"PHISH-{uuid.uuid4().hex[:8].upper()}"
        started_at = datetime.now(timezone.utc)
        samples = self._sample_emails(count, include_legitimate)
        results = []

        self._log_activity(
            {
                "event": "phishing_test_run_started",
                "action_type": "test_run_started",
                "module": "phishing",
                "session_id": session_id,
                "samples_requested": count,
                "timestamp": started_at,
            }
        )

        for index, sample in enumerate(samples, start=1):
            results.append(self._process_sample(sample, session_id, index))

        completed_at = datetime.now(timezone.utc)
        phishing_detected = sum(1 for item in results if item.get("is_phishing"))
        failed = sum(1 for item in results if not item.get("success"))

        summary = {
            "session_id": session_id,
            "started_at": started_at.isoformat(),
            "completed_at": completed_at.isoformat(),
            "total_scanned": len(results),
            "phishing_detected": phishing_detected,
            "safe_detected": len(results) - phishing_detected - failed,
            "failed": failed,
            "dataset_source": DATASET_SOURCE,
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
                "samples_processed": len(results),
                "phishing_detected": phishing_detected,
                "failed": failed,
                "timestamp": completed_at,
            }
        )

        return {
            "success": True,
            "session_id": session_id,
            "summary": summary,
            "results": results,
        }

    def _sample_emails(self, count: int, include_legitimate: bool) -> List[Dict[str, Any]]:
        if include_legitimate:
            phishing_count = max(1, int(round(count * 0.7)))
            legitimate_count = max(0, count - phishing_count)
        else:
            phishing_count = count
            legitimate_count = 0

        samples = []
        samples.extend(self._choose_with_replacement("phishing", phishing_count))
        samples.extend(self._choose_with_replacement("legitimate", legitimate_count))
        random.shuffle(samples)
        return samples

    def _choose_with_replacement(self, sample_type: str, count: int) -> List[Dict[str, Any]]:
        pool = self.dataset.get(sample_type, [])
        chosen = []
        for _ in range(count):
            sample = random.choice(pool).copy()
            sample["expected_label"] = sample_type
            sample["source"] = DATASET_SOURCE
            chosen.append(sample)
        return chosen

    def _process_sample(
        self,
        sample: Dict[str, Any],
        session_id: str,
        sample_index: int,
    ) -> Dict[str, Any]:
        email_id = f"{session_id}-{sample_index:03d}"
        full_content = self._build_email_content(sample)

        try:
            orchestrator = get_orchestrator_agent()
            pipeline_result = orchestrator.process_email(full_content, email_id)
            detection = pipeline_result.get("pipeline_results", {}).get("detection", {})
            explainability = pipeline_result.get("pipeline_results", {}).get("explainability", {})
            response = pipeline_result.get("pipeline_results", {}).get("response", {})

            is_phishing = bool(detection.get("is_phishing", False))
            confidence = self._confidence_percent(detection.get("confidence", 0))
            severity = pipeline_result.get("severity", detection.get("severity", "LOW"))
            actions_taken = response.get("actions_executed", []) or []

            scan_id = self._store_email_scan(
                sample=sample,
                session_id=session_id,
                email_id=email_id,
                pipeline_result=pipeline_result,
                is_phishing=is_phishing,
                confidence=confidence,
                severity=severity,
            )

            threat_id = None
            report_id = None
            if is_phishing:
                threat_id = self._store_threat(
                    sample=sample,
                    session_id=session_id,
                    scan_id=scan_id,
                    pipeline_result=pipeline_result,
                    confidence=confidence,
                    severity=severity,
                    actions_taken=actions_taken,
                )
                report_id = self._generate_report(
                    sample=sample,
                    threat_id=threat_id or pipeline_result.get("incident_id"),
                    pipeline_result=pipeline_result,
                    confidence=confidence,
                    severity=severity,
                    actions_taken=actions_taken,
                )
                self._attach_detection_artifacts(scan_id, threat_id, report_id)

            self._write_sample_logs(
                sample=sample,
                session_id=session_id,
                scan_id=scan_id,
                threat_id=threat_id,
                is_phishing=is_phishing,
                confidence=confidence,
                severity=severity,
                actions_taken=actions_taken,
            )

            return {
                "success": True,
                "sample_id": email_id,
                "scan_id": scan_id,
                "threat_id": threat_id,
                "incident_id": pipeline_result.get("incident_id"),
                "report_id": report_id,
                "sender": sample.get("sender"),
                "subject": sample.get("subject"),
                "expected_label": sample.get("expected_label"),
                "is_phishing": is_phishing,
                "confidence": confidence,
                "severity": severity,
                "actions_taken": actions_taken,
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
                    "email_subject": sample.get("subject"),
                    "sender": sample.get("sender"),
                    "error": str(exc),
                    "timestamp": datetime.now(timezone.utc),
                }
            )
            return {
                "success": False,
                "sample_id": email_id,
                "sender": sample.get("sender"),
                "subject": sample.get("subject"),
                "expected_label": sample.get("expected_label"),
                "error": str(exc),
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
        pipeline_result: Dict[str, Any],
        is_phishing: bool,
        confidence: float,
        severity: str,
    ) -> Optional[str]:
        scan_id = f"SCAN-{uuid.uuid4().hex[:8].upper()}"
        explainability = pipeline_result.get("pipeline_results", {}).get("explainability", {})
        scan_doc = {
            "scan_id": scan_id,
            "email_id": email_id,
            "session_id": session_id,
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
            "incident_id": pipeline_result.get("incident_id"),
            "processing_time_ms": pipeline_result.get("processing_time_ms", 0),
            "model_version": "2.0.0",
            "scanned_at": datetime.now(timezone.utc),
        }
        if self.repository:
            self.repository.save_scan(scan_doc)
        return scan_id

    def _store_threat(
        self,
        sample: Dict[str, Any],
        session_id: str,
        scan_id: Optional[str],
        pipeline_result: Dict[str, Any],
        confidence: float,
        severity: str,
        actions_taken: List[str],
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
            "detected_at": now,
            "updated_at": now,
            "resolved_at": now if actions_taken else None,
            "data_source": sample.get("source", DATASET_SOURCE),
            "expected_label": sample.get("expected_label"),
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
    ) -> None:
        updates = {}
        if threat_id:
            updates["threat_id"] = threat_id
        if report_id:
            updates["report_id"] = report_id

        if not updates:
            return

        if scan_id:
            if self.repository:
                self.repository.update_scan(scan_id, updates)

        if threat_id and report_id:
            if self.repository:
                self.repository.update_threat(threat_id, {"report_id": report_id})

    def _write_sample_logs(
        self,
        sample: Dict[str, Any],
        session_id: str,
        scan_id: Optional[str],
        threat_id: Optional[str],
        is_phishing: bool,
        confidence: float,
        severity: str,
        actions_taken: List[str],
    ) -> None:
        self._log_activity(
            {
                "event": "email_scanned",
                "action_type": "email_processed",
                "module": "phishing",
                "session_id": session_id,
                "scan_id": scan_id,
                "email_subject": sample.get("subject", "No Subject"),
                "sender": sample.get("sender", "Unknown"),
                "is_phishing": is_phishing,
                "is_threat": is_phishing,
                "confidence": confidence,
                "severity": severity,
                "expected": sample.get("expected_label"),
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
                "email_subject": sample.get("subject", "No Subject"),
                "sender": sample.get("sender", "Unknown"),
                "is_phishing": True,
                "is_threat": True,
                "confidence": confidence,
                "severity": severity,
                "actions": actions_taken,
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
                    "email_subject": sample.get("subject", "No Subject"),
                    "sender": sample.get("sender", "Unknown"),
                    "is_phishing": True,
                    "is_threat": True,
                    "confidence": confidence,
                    "severity": severity,
                    "resolution": "automated_response",
                    "actions": actions_taken,
                    "timestamp": datetime.now(timezone.utc),
                }
            )

    def _log_activity(self, log_data: Dict[str, Any]) -> None:
        log_data.setdefault("id", f"ACT-{uuid.uuid4().hex[:12].upper()}")
        log_data.setdefault("timestamp", datetime.now(timezone.utc))
        log_data["created_at"] = datetime.now(timezone.utc)
        if self.repository:
            self.repository.save_activity_log(log_data)

    def _confidence_percent(self, value: Any) -> float:
        try:
            confidence = float(value or 0)
        except (TypeError, ValueError):
            confidence = 0.0
        if confidence <= 1:
            confidence *= 100
        return round(confidence, 1)


_service_instance: Optional[PhishingTestRunService] = None


def get_phishing_test_run_service() -> PhishingTestRunService:
    global _service_instance
    if _service_instance is None:
        _service_instance = PhishingTestRunService()
    return _service_instance
