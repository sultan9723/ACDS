"""
SOC Audit Logs API
==================
File-backed audit log endpoint derived from normalized incidents.
"""

import json
from pathlib import Path
from typing import Any, Dict, List, Optional

from fastapi import APIRouter, Query


router = APIRouter(prefix="/logs", tags=["SOC Logs"])

PROJECT_ROOT = Path(__file__).resolve().parents[3]
INCIDENTS_DB_PATH = PROJECT_ROOT / "data" / "incidents.json"


def load_incidents() -> List[Dict[str, Any]]:
    if not INCIDENTS_DB_PATH.exists():
        return []

    try:
        with INCIDENTS_DB_PATH.open("r", encoding="utf-8") as handle:
            data = json.load(handle)
    except Exception as exc:
        print(f"Failed to load incidents.json for logs: {exc}")
        return []

    incidents = data.get("incidents", []) if isinstance(data, dict) else []
    return incidents if isinstance(incidents, list) else []


def classify_agent(action: str) -> str:
    text = action.lower()
    if "detection" in text:
        return "Detection Agent"
    if any(token in text for token in ("evidence", "feature", "explain", "pe-header", "pe header")):
        return "Explainability Agent"
    if any(token in text for token in ("response", "recommended", "quarantine", "isolate")):
        return "Response Agent"
    if any(token in text for token in ("report", "persisted")):
        return "Report Agent"
    return "Orchestrator Agent"


def incident_to_log_rows(incident: Dict[str, Any]) -> List[Dict[str, Any]]:
    actions = incident.get("actions_taken") or []
    if isinstance(actions, str):
        actions = [actions]
    if not actions:
        actions = ["Incident recorded"]

    timestamp = (
        incident.get("timestamp")
        or incident.get("created_at")
        or incident.get("detected_at")
        or "Unknown"
    )
    incident_id = incident.get("incident_id") or incident.get("threat_id") or "Unknown"
    module = incident.get("module") or incident.get("threat_type") or "Unknown"
    severity = incident.get("severity") or "Unknown"
    status = incident.get("status") or incident.get("lifecycle_state") or "Unknown"
    processing_time_ms = incident.get("processing_time_ms")

    rows = []
    for index, action in enumerate(actions):
        action_text = str(action) if action else "Unknown"
        row = {
            "id": f"{incident_id}-{index}",
            "timestamp": timestamp,
            "created_at": incident.get("created_at") or timestamp,
            "incident_id": incident_id,
            "module": module,
            "agent": classify_agent(action_text),
            "action": action_text or "Unknown",
            "severity": severity,
            "status": status,
            "lifecycle_state": incident.get("lifecycle_state") or status,
        }
        if processing_time_ms is not None:
            row["processing_time_ms"] = processing_time_ms
        rows.append(row)

    return rows


@router.get("")
@router.get("/")
async def get_soc_logs(
    limit: int = Query(200, ge=1, le=1000),
    module: Optional[str] = Query(None),
    include_failed: bool = Query(False),
):
    """Return SOC audit logs derived from data/incidents.json."""
    logs: List[Dict[str, Any]] = []
    for incident in load_incidents():
        if module and str(incident.get("module", "")).lower() != module.lower():
            continue
        if not include_failed and str(incident.get("lifecycle_state", "")).lower() == "analysis_failed":
            continue
        logs.extend(incident_to_log_rows(incident))

    logs.sort(key=lambda row: row.get("timestamp") or "", reverse=True)
    return {"success": True, "logs": logs[:limit]}
