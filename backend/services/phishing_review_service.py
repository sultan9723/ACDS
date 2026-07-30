"""
Phishing analyst review workflow.

Adds a lightweight review state around phishing scans/threats without changing
the detection pipeline. Review state is persisted through the phishing
repository so it works with MongoDB and the local degraded store.
"""

import uuid
from datetime import datetime, timezone
from typing import Any, Dict, List, Optional

try:
    from services.phishing_repository import get_phishing_repository
except ImportError:
    try:
        from backend.services.phishing_repository import get_phishing_repository
    except ImportError:
        get_phishing_repository = None


VALID_VERDICTS = {
    "true_positive",
    "false_positive",
    "false_negative",
    "true_negative",
    "needs_review",
}


class PhishingReviewService:
    def __init__(self) -> None:
        self.repository = get_phishing_repository() if get_phishing_repository else None

    def list_review_queue(
        self,
        limit: int = 50,
        status: Optional[str] = None,
        include_reviewed: bool = False,
    ) -> Dict[str, Any]:
        if self.repository is None:
            return {"items": [], "data_source": "empty"}

        scan_result = self.repository.list_scans(limit=500)
        threat_result = self.repository.list_threats(limit=500)
        threats_by_scan = {
            threat.get("scan_id"): threat
            for threat in threat_result.records
            if threat.get("scan_id")
        }

        items = []
        for scan in scan_result.records:
            item = self._build_review_item(scan, threats_by_scan.get(scan.get("scan_id")))
            if not status and not include_reviewed and item["review_status"] == "not_required":
                continue
            if not include_reviewed and item["review_status"] == "reviewed":
                continue
            if status and item["review_status"] != status:
                continue
            items.append(item)

        items.sort(
            key=lambda item: (
                item["review_priority"],
                item.get("scanned_at") or "",
            ),
            reverse=True,
        )
        return {
            "items": items[:limit],
            "data_source": scan_result.data_source,
        }

    def submit_review(
        self,
        scan_id: str,
        verdict: str,
        analyst: Optional[str] = None,
        notes: Optional[str] = None,
    ) -> Dict[str, Any]:
        if self.repository is None:
            raise RuntimeError("Phishing repository is not available")

        normalized_verdict = self._normalize_verdict(verdict)
        scan = self.repository.get_scan(scan_id)
        if not scan:
            raise ValueError(f"Scan {scan_id} was not found")

        threat_id = scan.get("threat_id")
        threat = self.repository.get_threat(threat_id) if threat_id else self._find_threat_for_scan(scan_id)
        threat_id = threat_id or (threat or {}).get("threat_id")
        reviewed_at = datetime.now(timezone.utc)
        feedback_type = self._feedback_type(normalized_verdict)
        review_id = f"PHREV-{uuid.uuid4().hex[:10].upper()}"
        correct_label = self._correct_label(normalized_verdict)

        updates = {
            "review_id": review_id,
            "review_status": "needs_review" if normalized_verdict == "needs_review" else "reviewed",
            "analyst_verdict": normalized_verdict,
            "feedback_type": feedback_type,
            "correct_label": correct_label,
            "review_notes": notes,
            "reviewed_by": analyst or "analyst",
            "reviewed_at": reviewed_at,
            "updated_at": reviewed_at,
        }

        if normalized_verdict == "false_positive":
            updates["status"] = "false_positive"
            updates["resolved_at"] = reviewed_at
        elif normalized_verdict in {"true_positive", "true_negative"}:
            updates["status"] = "resolved"
            updates["resolved_at"] = reviewed_at
        elif normalized_verdict == "false_negative":
            updates["status"] = "active"

        self.repository.update_scan(scan_id, updates)
        if threat_id:
            self.repository.update_threat(threat_id, updates)

        log_doc = {
            "id": f"ACT-{uuid.uuid4().hex[:12].upper()}",
            "event": "analyst_review_submitted",
            "action_type": "analyst_review",
            "module": "phishing",
            "scan_id": scan_id,
            "threat_id": threat_id,
            "review_id": review_id,
            "review_status": updates["review_status"],
            "analyst_verdict": normalized_verdict,
            "feedback_type": feedback_type,
            "correct_label": correct_label,
            "reviewed_by": updates["reviewed_by"],
            "review_notes": notes,
            "email_subject": scan.get("email_subject"),
            "sender": scan.get("email_sender"),
            "is_phishing": bool(scan.get("is_phishing")),
            "is_threat": bool(scan.get("is_phishing") or threat),
            "confidence": scan.get("confidence"),
            "severity": scan.get("risk_level") or (threat or {}).get("severity"),
            "timestamp": reviewed_at,
            "created_at": reviewed_at,
        }
        self.repository.save_activity_log(log_doc)

        return {
            "review_id": review_id,
            "scan_id": scan_id,
            "threat_id": threat_id,
            "review_status": updates["review_status"],
            "analyst_verdict": normalized_verdict,
            "feedback_type": feedback_type,
            "correct_label": correct_label,
            "reviewed_at": reviewed_at.isoformat(),
        }

    def _build_review_item(
        self,
        scan: Dict[str, Any],
        threat: Optional[Dict[str, Any]],
    ) -> Dict[str, Any]:
        expected = scan.get("expected_label")
        predicted = scan.get("predicted_label") or ("phishing" if scan.get("is_phishing") else "legitimate")
        correct = scan.get("correct")
        outcome = scan.get("evaluation_outcome")
        review_status = scan.get("review_status") or self._default_review_status(scan, threat)
        priority = self._priority(review_status, outcome, threat)

        return {
            "scan_id": scan.get("scan_id"),
            "threat_id": scan.get("threat_id") or (threat or {}).get("threat_id"),
            "incident_id": scan.get("incident_id") or (threat or {}).get("incident_id"),
            "report_id": scan.get("report_id") or (threat or {}).get("report_id"),
            "sender": scan.get("email_sender"),
            "subject": scan.get("email_subject"),
            "prediction": predicted,
            "expected_label": expected,
            "correct": correct,
            "evaluation_outcome": outcome,
            "confidence": scan.get("confidence"),
            "severity": scan.get("risk_level") or (threat or {}).get("severity"),
            "review_status": review_status,
            "review_priority": priority,
            "analyst_verdict": scan.get("analyst_verdict") or (threat or {}).get("analyst_verdict"),
            "feedback_type": scan.get("feedback_type") or (threat or {}).get("feedback_type"),
            "reviewed_by": scan.get("reviewed_by") or (threat or {}).get("reviewed_by"),
            "reviewed_at": self._safe_iso(scan.get("reviewed_at") or (threat or {}).get("reviewed_at")),
            "review_notes": scan.get("review_notes") or (threat or {}).get("review_notes"),
            "scanned_at": self._safe_iso(scan.get("scanned_at")),
            "data_source": scan.get("data_source"),
        }

    def _find_threat_for_scan(self, scan_id: str) -> Optional[Dict[str, Any]]:
        if self.repository is None:
            return None
        for threat in self.repository.list_threats(limit=500).records:
            if threat.get("scan_id") == scan_id:
                return threat
        return None

    def _default_review_status(self, scan: Dict[str, Any], threat: Optional[Dict[str, Any]]) -> str:
        if scan.get("analyst_verdict") or (threat or {}).get("analyst_verdict"):
            return "reviewed"
        if scan.get("correct") is False or scan.get("evaluation_outcome") in {"false_positive", "false_negative"}:
            return "needs_review"
        if scan.get("report_id") or (threat or {}).get("report_id"):
            return "ready_for_review"
        if scan.get("is_phishing") or threat:
            return "ready_for_review"
        return "not_required"

    def _priority(self, review_status: str, outcome: Optional[str], threat: Optional[Dict[str, Any]]) -> int:
        if outcome in {"false_positive", "false_negative"}:
            return 100
        if review_status == "needs_review":
            return 90
        if threat:
            return 70
        if review_status == "ready_for_review":
            return 50
        return 10

    def _normalize_verdict(self, verdict: str) -> str:
        normalized = str(verdict or "").strip().lower()
        if normalized not in VALID_VERDICTS:
            raise ValueError(f"Invalid analyst verdict. Must be one of: {sorted(VALID_VERDICTS)}")
        return normalized

    def _feedback_type(self, verdict: str) -> str:
        if verdict in {"true_positive", "true_negative"}:
            return "correct_detection"
        if verdict in {"false_positive", "false_negative"}:
            return verdict
        return "general_feedback"

    def _correct_label(self, verdict: str) -> Optional[bool]:
        if verdict in {"true_positive", "false_negative"}:
            return True
        if verdict in {"true_negative", "false_positive"}:
            return False
        return None

    def _safe_iso(self, value: Any) -> Optional[str]:
        if hasattr(value, "isoformat"):
            return value.isoformat()
        return str(value) if value else None


_review_service: Optional[PhishingReviewService] = None


def get_phishing_review_service() -> PhishingReviewService:
    global _review_service
    if _review_service is None:
        _review_service = PhishingReviewService()
    return _review_service
