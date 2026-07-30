"""
Phishing lifecycle trace helpers.

Builds a stable, UI-friendly view of the Email Phishing pipeline without
duplicating orchestration logic in routes and persistence services.
"""

from datetime import datetime, timezone
from typing import Any, Dict, List, Optional


def build_phishing_lifecycle_trace(
    pipeline_result: Optional[Dict[str, Any]],
    *,
    is_phishing: bool,
    actions_taken: Optional[List[str]] = None,
    report_id: Optional[str] = None,
    report_generated_at: Optional[str] = None,
) -> Dict[str, Any]:
    pipeline_result = pipeline_result or {}
    pipeline_results = pipeline_result.get("pipeline_results", {}) or {}
    detection = pipeline_results.get("detection", {}) or {}
    explainability = pipeline_results.get("explainability", {}) or {}
    response = pipeline_results.get("response", {}) or {}
    actions = normalize_response_actions(response, actions_taken)
    now = _utc_now_iso()

    report_status = "generated" if report_id else ("pending" if is_phishing else "not_required")
    lifecycle_state = _resolve_lifecycle_state(
        pipeline_result=pipeline_result,
        is_phishing=is_phishing,
        actions=actions,
        report_id=report_id,
    )

    stages = [
        {
            "state": "detected",
            "label": "Detection",
            "status": "completed",
            "agent": "detection",
            "timestamp": pipeline_result.get("timestamp") or now,
            "summary": "Email classified as phishing" if is_phishing else "Email classified as safe",
            "metadata": {
                "is_phishing": is_phishing,
                "confidence": detection.get("confidence", pipeline_result.get("confidence")),
                "risk_score": pipeline_result.get("risk_score", detection.get("risk_score", 0)),
                "severity": pipeline_result.get("severity", detection.get("severity", "LOW")),
            },
        },
        {
            "state": "analyzing",
            "label": "Explainability",
            "status": "completed" if explainability else "skipped",
            "agent": "explainability",
            "timestamp": now,
            "summary": _explainability_summary(explainability),
            "metadata": {
                "evidence_count": len(explainability.get("evidence", []) or []),
                "ioc_count": _count_iocs(explainability.get("iocs", {})),
            },
        },
    ]

    if is_phishing:
        stages.append(
            {
                "state": "responded",
                "label": "Response",
                "status": "completed" if actions else "pending",
                "agent": "response",
                "timestamp": response.get("timestamp") or now,
                "summary": response.get("recommendation")
                or ("Automated response actions executed" if actions else "Response action pending"),
                "metadata": {
                    "actions": actions,
                    "response_details": response.get("response_details", {}),
                    "actions_pending": response.get("actions_pending", []),
                },
            }
        )
        stages.append(
            {
                "state": "reported",
                "label": "Report",
                "status": report_status,
                "agent": "reporting",
                "timestamp": report_generated_at or now,
                "summary": "Incident report generated" if report_id else "Incident report not generated yet",
                "metadata": {
                    "report_id": report_id,
                },
            }
        )
    else:
        stages.append(
            {
                "state": "resolved",
                "label": "Resolution",
                "status": "completed",
                "agent": "orchestrator",
                "timestamp": now,
                "summary": "No response required for safe email",
                "metadata": {
                    "actions": [],
                },
            }
        )

    return {
        "state": lifecycle_state,
        "report_status": report_status,
        "actions": actions,
        "response_summary": response.get("recommendation") or _response_summary(actions, is_phishing),
        "response_details": response.get("response_details", {}),
        "stages": stages,
    }


def normalize_response_actions(
    response: Optional[Dict[str, Any]],
    actions_taken: Optional[List[str]] = None,
) -> List[str]:
    response = response or {}
    actions = response.get("actions_executed") or actions_taken or []
    return [str(action) for action in actions if action]


def _resolve_lifecycle_state(
    *,
    pipeline_result: Dict[str, Any],
    is_phishing: bool,
    actions: List[str],
    report_id: Optional[str],
) -> str:
    if report_id:
        return "reported"
    if is_phishing and actions:
        return "responded"
    if is_phishing:
        state = pipeline_result.get("lifecycle_state")
        return state if state in {"responded", "resolved"} else "detected"
    return "resolved"


def _explainability_summary(explainability: Dict[str, Any]) -> str:
    if explainability.get("explanation"):
        return str(explainability["explanation"])
    evidence_count = len(explainability.get("evidence", []) or [])
    if evidence_count:
        return f"{evidence_count} evidence item(s) extracted"
    return "No explainability artifacts available"


def _response_summary(actions: List[str], is_phishing: bool) -> str:
    if actions:
        return f"{len(actions)} automated response action(s) executed"
    if is_phishing:
        return "Response action pending"
    return "No response required"


def _count_iocs(iocs: Any) -> int:
    if isinstance(iocs, dict):
        return sum(len(value) if isinstance(value, list) else int(bool(value)) for value in iocs.values())
    if isinstance(iocs, list):
        return len(iocs)
    return 0


def _utc_now_iso() -> str:
    return datetime.now(timezone.utc).isoformat()
