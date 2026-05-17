"""
Demo API Routes
================
API endpoints for demo mode and automated testing.
Controls the demo scheduler for presentations and testing.
"""

import json
import time
import uuid
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Dict, List, Optional
from fastapi import APIRouter, HTTPException, Query
from pydantic import BaseModel, Field

router = APIRouter(prefix="/demo", tags=["Demo Mode"])

PROJECT_ROOT = Path(__file__).resolve().parents[3]
INCIDENTS_DB_PATH = PROJECT_ROOT / "data" / "incidents.json"
RANSOMWARE_MODEL_WARNING = "Ransomware static PE analysis completed, but ML model artifact is not loaded."


class DemoStartRequest(BaseModel):
    interval_seconds: int = Field(default=300, ge=30, le=3600, description="Interval between batches in seconds")
    batch_size: int = Field(default=5, ge=1, le=20, description="Number of emails per batch")


class ManualBatchRequest(BaseModel):
    count: int = Field(default=5, ge=1, le=50, description="Number of emails to process")


class FullSocRunRequest(BaseModel):
    phishing: int = Field(default=5, ge=1, le=20, description="Email phishing samples to process")
    malware: int = Field(default=5, ge=1, le=20, description="Malware samples to process")
    credential_stuffing: int = Field(default=5, ge=1, le=20, description="Credential stuffing events to process")
    ransomware: int = Field(default=2, ge=1, le=10, description="Uploaded ransomware executables to analyze")


def _utc_now() -> datetime:
    return datetime.now(timezone.utc)


def _utc_iso() -> str:
    return _utc_now().isoformat()


def _safe_float(value: Any, default: float = 0.0) -> float:
    try:
        number = float(value)
    except (TypeError, ValueError):
        return default
    if number > 1:
        number = number / 100
    return round(max(0.0, min(number, 1.0)), 4)


def _normalize_severity(value: Any, default: str = "LOW") -> str:
    severity = str(value or default).upper()
    return severity if severity in {"LOW", "MEDIUM", "HIGH", "CRITICAL"} else default


def _as_list(value: Any) -> List[str]:
    if value is None:
        return []
    if isinstance(value, list):
        return [str(item) for item in value if item is not None]
    if isinstance(value, tuple):
        return [str(item) for item in value if item is not None]
    return [str(value)]


def _load_incident_db() -> Dict[str, Any]:
    if not INCIDENTS_DB_PATH.exists():
        return {"schema_version": "2.0.0", "incidents": []}

    try:
        with INCIDENTS_DB_PATH.open("r", encoding="utf-8") as handle:
            data = json.load(handle)
    except (json.JSONDecodeError, OSError):
        return {"schema_version": "2.0.0", "incidents": []}

    if isinstance(data, list):
        return {"schema_version": "2.0.0", "incidents": data}
    if not isinstance(data, dict):
        return {"schema_version": "2.0.0", "incidents": []}
    data.setdefault("schema_version", "2.0.0")
    data.setdefault("incidents", [])
    if not isinstance(data["incidents"], list):
        data["incidents"] = []
    return data


def _persist_incidents(incidents: List[Dict[str, Any]]) -> Dict[str, int]:
    db = _load_incident_db()
    existing_by_id = {
        str(item.get("incident_id")): index
        for index, item in enumerate(db.get("incidents", []))
        if isinstance(item, dict) and item.get("incident_id")
    }
    added = 0
    updated = 0
    for incident in incidents:
        incident_id = str(incident.get("incident_id", "")).strip()
        if not incident_id:
            continue
        if incident_id in existing_by_id:
            index = existing_by_id[incident_id]
            existing = db["incidents"][index] if isinstance(db["incidents"][index], dict) else {}
            db["incidents"][index] = {**existing, **incident}
            updated += 1
            continue
        db["incidents"].append(incident)
        existing_by_id[incident_id] = len(db["incidents"]) - 1
        added += 1

    INCIDENTS_DB_PATH.parent.mkdir(parents=True, exist_ok=True)
    with INCIDENTS_DB_PATH.open("w", encoding="utf-8") as handle:
        json.dump(db, handle, indent=2, ensure_ascii=False)
    return {"added": added, "updated": updated}


def _default_actions(module_label: str, threat: bool) -> List[str]:
    state = "threat" if threat else "safe sample"
    return [
        f"Detection Agent completed {module_label} detection for {state}.",
        f"Explainability Agent recorded evidence and feature indicators for {module_label}.",
        f"Response Agent recommended SOC response actions for {module_label}.",
        f"Report Agent persisted {module_label} incident for audit trail and reporting.",
    ]


def _recommended_actions(module: str, threat: bool, existing: Any = None) -> List[str]:
    actions = _as_list(existing)
    if actions:
        return actions
    if not threat:
        return ["Continue monitoring and retain the event for baseline comparison."]
    defaults = {
        "phishing": ["Quarantine suspicious email.", "Block sender or domain.", "Review affected mailbox activity."],
        "malware": ["Isolate affected host.", "Collect file hash and telemetry.", "Run endpoint containment workflow."],
        "ransomware": ["Isolate impacted endpoint.", "Preserve executable for forensic review.", "Validate backups before recovery."],
        "credential_stuffing": ["Rate-limit source IP.", "Force password reset for targeted accounts.", "Enable MFA challenge."],
    }
    return defaults.get(module, ["Review incident and apply SOC response playbook."])


def _normalize_common(
    *,
    incident_id: str,
    module: str,
    title: str,
    prediction: str,
    severity: Any,
    confidence: Any,
    threat: bool,
    summary: str,
    evidence: Any = None,
    recommended_actions: Any = None,
    actions_taken: Any = None,
    created_at: Optional[str] = None,
    status: Optional[str] = None,
    lifecycle_state: Optional[str] = None,
) -> Dict[str, Any]:
    normalized_status = status or ("detected" if threat else "closed")
    normalized_lifecycle = lifecycle_state or ("responded" if threat else "closed")
    action_list = _as_list(actions_taken) or _default_actions(module.replace("_", " "), threat)
    return {
        "incident_id": incident_id,
        "module": module,
        "title": title,
        "prediction": prediction,
        "severity": _normalize_severity(severity),
        "confidence": _safe_float(confidence),
        "status": normalized_status,
        "lifecycle_state": normalized_lifecycle,
        "summary": summary,
        "evidence": _as_list(evidence),
        "recommended_actions": _recommended_actions(module, threat, recommended_actions),
        "actions_taken": action_list,
        "created_at": created_at or _utc_iso(),
    }


def _normalize_phishing_result(result: Dict[str, Any], run_id: str, index: int) -> Dict[str, Any]:
    detection = result.get("pipeline_results", {}).get("detection", {}) if isinstance(result.get("pipeline_results"), dict) else {}
    is_failed = not result.get("success", True)
    is_threat = bool(result.get("is_phishing") or detection.get("is_phishing"))
    incident_id = result.get("incident_id") or result.get("threat_id") or f"{run_id}-PHISH-{index + 1:03d}"
    severity = result.get("severity") or detection.get("severity") or ("MEDIUM" if is_threat else "LOW")
    confidence = result.get("confidence") or detection.get("confidence") or (0.0 if is_failed else 0.55)
    expected = result.get("expected", "unknown")
    title = result.get("subject") or f"Email phishing sample ({expected})"
    evidence = result.get("evidence") or detection.get("evidence") or detection.get("indicators")
    if not evidence:
        evidence = [f"Expected label: {expected}", "Email content processed through phishing detection workflow."]
    return _normalize_common(
        incident_id=str(incident_id),
        module="phishing",
        title=title,
        prediction="PHISHING" if is_threat else "SAFE",
        severity=severity,
        confidence=confidence,
        threat=is_threat,
        status="analysis_failed" if is_failed else ("detected" if is_threat else "closed"),
        lifecycle_state="analysis_failed" if is_failed else ("responded" if is_threat else "closed"),
        summary="Email phishing workflow identified a suspicious message." if is_threat else "Email phishing workflow classified the message as safe.",
        evidence=evidence,
        actions_taken=result.get("actions_taken"),
    )


def _normalize_malware_result(result: Dict[str, Any], run_id: str, index: int) -> Dict[str, Any]:
    pipeline = result.get("pipeline_results", {}) if isinstance(result.get("pipeline_results"), dict) else {}
    detection = pipeline.get("detection", {}) if isinstance(pipeline.get("detection"), dict) else {}
    response = pipeline.get("response", {}) if isinstance(pipeline.get("response"), dict) else {}
    is_failed = not result.get("success", True)
    is_threat = bool(result.get("is_malware") or detection.get("is_malware"))
    filename = result.get("filename") or result.get("sample_id") or "malware_demo_sample"
    incident_id = result.get("incident_id") or f"{run_id}-MAL-{index + 1:03d}"
    evidence = result.get("evidence") or detection.get("evidence") or detection.get("indicators")
    if not evidence:
        evidence = [f"Sample: {filename}", "Behavioral metadata processed through malware detection workflow."]
    return _normalize_common(
        incident_id=str(incident_id),
        module="malware",
        title=f"Malware sample analysis: {filename}",
        prediction="MALWARE" if is_threat else "SAFE",
        severity=result.get("severity") or detection.get("severity") or ("HIGH" if is_threat else "LOW"),
        confidence=result.get("confidence") or detection.get("confidence") or (0.0 if is_failed else 0.55),
        threat=is_threat,
        status="analysis_failed" if is_failed else ("detected" if is_threat else "closed"),
        lifecycle_state="analysis_failed" if is_failed else ("responded" if is_threat else "closed"),
        summary="Malware workflow identified suspicious behavioral indicators." if is_threat else "Malware workflow classified the sample as safe.",
        evidence=evidence,
        recommended_actions=response.get("recommended_actions") or response.get("actions_recommended"),
        actions_taken=result.get("actions_taken") or response.get("actions_executed"),
    )


def _normalize_ransomware_result(result: Dict[str, Any], run_id: str, index: int) -> Dict[str, Any]:
    is_failed = str(result.get("lifecycle_state", "")).lower() == "analysis_failed"
    is_threat = str(result.get("prediction", "")).upper() == "RANSOMWARE"
    filename = result.get("filename") or "uploaded_executable"
    return _normalize_common(
        incident_id=str(result.get("incident_id") or f"{run_id}-RANSOM-{index + 1:03d}"),
        module="ransomware",
        title=f"Uploaded executable analysis: {filename}",
        prediction="RANSOMWARE" if is_threat else "SAFE",
        severity=result.get("severity") or ("HIGH" if is_threat else "LOW"),
        confidence=result.get("confidence", 0),
        threat=is_threat,
        status="analysis_failed" if is_failed else ("detected" if is_threat else "closed"),
        lifecycle_state=result.get("lifecycle_state") or ("responded" if is_threat else "closed"),
        summary=f"Static PE analysis completed for {filename} without executing the file.",
        evidence=result.get("evidence"),
        recommended_actions=result.get("recommended_actions"),
        actions_taken=result.get("actions_taken"),
        created_at=result.get("created_at"),
    )


def _normalize_credential_result(result: Dict[str, Any], run_id: str) -> Dict[str, Any]:
    is_threat = bool(result.get("alert_created") or _safe_float(result.get("risk_score")) >= 0.4)
    alert_id = result.get("alert_id") or f"{run_id}-CRED-001"
    evidence = result.get("evidence") or [
        f"Events created: {result.get('events_created', 0)}",
        f"Source IP: {result.get('source_ip', '198.51.100.25')}",
    ]
    recommended = result.get("recommended_action")
    return _normalize_common(
        incident_id=str(alert_id),
        module="credential_stuffing",
        title="Credential stuffing login burst analysis",
        prediction="CREDENTIAL_STUFFING" if is_threat else "SAFE",
        severity=result.get("severity") or ("MEDIUM" if is_threat else "LOW"),
        confidence=result.get("confidence") or result.get("risk_score") or 0,
        threat=is_threat,
        status="detected" if is_threat else "closed",
        lifecycle_state="responded" if is_threat else "closed",
        summary="Credential stuffing workflow detected a burst of failed login attempts." if is_threat else "Credential stuffing workflow did not detect a coordinated login attack.",
        evidence=evidence,
        recommended_actions=[recommended] if recommended else None,
        actions_taken=[
            "Detection Agent analyzed credential stuffing login burst.",
            "Explainability Agent recorded behavioral features and evidence.",
            f"Response Agent recommended action: {recommended or 'log_only'}.",
            "Report Agent persisted credential stuffing incident for audit trail and reporting.",
        ],
    )


def _build_module_breakdown(module: str, incidents: List[Dict[str, Any]], status: str = "completed", warning: Optional[str] = None) -> Dict[str, Any]:
    threats = sum(1 for incident in incidents if incident.get("prediction") != "SAFE")
    return {
        "module": module,
        "processed": len(incidents),
        "threats": threats,
        "safe": len(incidents) - threats,
        "status": status,
        "warning": warning,
    }


@router.post("/start")
async def start_demo_mode(request: DemoStartRequest = DemoStartRequest()):
    """
    Start the demo scheduler.
    
    This will begin automatically processing sample emails at regular intervals.
    Useful for demonstrations and testing the system's capabilities.
    """
    try:
        from services.demo_scheduler import get_demo_scheduler
        
        scheduler = get_demo_scheduler()
        
        # Set interval if specified
        if request.interval_seconds:
            scheduler.set_interval(request.interval_seconds)
        
        result = await scheduler.start()
        
        return {
            "success": True,
            "message": f"Demo mode started. Processing {request.batch_size} emails every {request.interval_seconds} seconds.",
            "status": result["status"],
            "interval_seconds": scheduler.interval_seconds,
            "next_run": (datetime.now(timezone.utc).replace(microsecond=0)).isoformat()
        }
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))


@router.post("/stop")
async def stop_demo_mode():
    """
    Stop the demo scheduler.
    """
    try:
        from services.demo_scheduler import get_demo_scheduler
        
        scheduler = get_demo_scheduler()
        result = await scheduler.stop()
        
        return {
            "success": True,
            "message": "Demo mode stopped.",
            "status": result["status"]
        }
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))


@router.get("/status")
async def get_demo_status():
    """
    Get the current status of the demo scheduler.
    """
    try:
        from services.demo_scheduler import get_demo_scheduler
        
        scheduler = get_demo_scheduler()
        stats = scheduler.stats
        
        return {
            "success": True,
            "running": scheduler.running,
            "interval_seconds": scheduler.interval_seconds,
            "stats": {
                "total_processed": stats["total_processed"],
                "phishing_detected": stats["phishing_detected"],
                "legitimate_detected": stats["legitimate_detected"],
                "last_run": stats["last_run"],
                "next_run": stats["next_run"]
            },
            "recent_sessions": stats["sessions"][-5:]
        }
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))


@router.post("/run-batch")
async def run_manual_batch(request: ManualBatchRequest = ManualBatchRequest()):
    """
    Manually trigger a batch of email processing.
    
    Use this to immediately process emails without waiting for the scheduler.
    """
    try:
        from services.demo_scheduler import get_demo_scheduler
        
        scheduler = get_demo_scheduler()
        result = await scheduler.process_batch(count=request.count)
        
        return {
            "success": True,
            "message": f"Processed {request.count} emails",
            "session_id": result["session_id"],
            "summary": result["summary"],
            "results": result["results"]
        }
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))


@router.post("/full-soc-run")
async def run_full_soc_demo(request: FullSocRunRequest = FullSocRunRequest()):
    """
    Run a controlled end-to-end SOC demo across ACDS modules.

    Each module is isolated so one failed workflow does not prevent the
    remaining demo modules from producing analyst-ready incidents.
    """
    started = _utc_now()
    started_at = started.isoformat()
    run_id = f"SOC-RUN-{started.strftime('%Y%m%d%H%M%S')}-{uuid.uuid4().hex[:6].upper()}"
    all_incidents: List[Dict[str, Any]] = []
    module_breakdown: List[Dict[str, Any]] = []
    warnings: List[str] = []
    start_timer = time.perf_counter()

    try:
        try:
            from services.demo_scheduler import get_demo_scheduler

            scheduler = get_demo_scheduler()
            result = await scheduler.process_batch(count=request.phishing)
            incidents = [
                _normalize_phishing_result(item, run_id, index)
                for index, item in enumerate(result.get("results", []))
            ]
            all_incidents.extend(incidents)
            module_breakdown.append(_build_module_breakdown("phishing", incidents))
        except Exception as exc:
            reason = f"phishing module failed: {exc}"
            warnings.append(reason)
            module_breakdown.append({
                "module": "phishing",
                "processed": 0,
                "threats": 0,
                "safe": 0,
                "status": "failed",
                "warning": reason,
            })

        try:
            from services.malware_demo_scheduler import get_malware_demo_scheduler

            scheduler = get_malware_demo_scheduler()
            result = await scheduler.process_batch(count=request.malware)
            incidents = [
                _normalize_malware_result(item, run_id, index)
                for index, item in enumerate(result.get("results", []))
            ]
            all_incidents.extend(incidents)
            module_breakdown.append(_build_module_breakdown("malware", incidents))
        except Exception as exc:
            reason = f"malware module failed: {exc}"
            warnings.append(reason)
            module_breakdown.append({
                "module": "malware",
                "processed": 0,
                "threats": 0,
                "safe": 0,
                "status": "failed",
                "warning": reason,
            })

        try:
            from api.routes.ransomware import analyze_uploaded_ransomware_executables

            result = await analyze_uploaded_ransomware_executables(batch_size=request.ransomware, offset=0)
            incidents = [
                _normalize_ransomware_result(item, run_id, index)
                for index, item in enumerate(result.get("results", []))
            ]
            warning = None
            if result.get("model_loaded") is False:
                warning = RANSOMWARE_MODEL_WARNING
                warnings.append(warning)
            all_incidents.extend(incidents)
            module_breakdown.append(_build_module_breakdown("ransomware", incidents, warning=warning))
        except Exception as exc:
            reason = f"ransomware module failed: {exc}"
            warnings.append(reason)
            module_breakdown.append({
                "module": "ransomware",
                "processed": 0,
                "threats": 0,
                "safe": 0,
                "status": "failed",
                "warning": reason,
            })

        try:
            from services.credential_stuffing_service import get_credential_stuffing_service

            service = get_credential_stuffing_service()
            result = service.simulate_attack(
                source_ip="198.51.100.25",
                username_prefix="demo_user",
                count=request.credential_stuffing,
            )
            incidents = [_normalize_credential_result(result, run_id)]
            all_incidents.extend(incidents)
            module_breakdown.append(_build_module_breakdown("credential_stuffing", incidents))
        except Exception as exc:
            reason = f"credential_stuffing module failed: {exc}"
            warnings.append(reason)
            module_breakdown.append({
                "module": "credential_stuffing",
                "processed": 0,
                "threats": 0,
                "safe": 0,
                "status": "failed",
                "warning": reason,
            })

        persistence = _persist_incidents(all_incidents)
        if persistence["updated"]:
            warnings.append("Existing incident IDs were updated in data/incidents.json instead of duplicated.")

        completed_at = _utc_iso()
        processing_time_ms = int((time.perf_counter() - start_timer) * 1000)
        threats_detected = sum(1 for incident in all_incidents if incident.get("prediction") != "SAFE")
        safe_detected = len(all_incidents) - threats_detected
        severity_breakdown = {"critical": 0, "high": 0, "medium": 0, "low": 0}
        for incident in all_incidents:
            key = str(incident.get("severity", "LOW")).lower()
            if key in severity_breakdown:
                severity_breakdown[key] += 1

        return {
            "success": True,
            "run_id": run_id,
            "started_at": started_at,
            "completed_at": completed_at,
            "processing_time_ms": processing_time_ms,
            "modules_processed": len(module_breakdown),
            "total_processed": len(all_incidents),
            "threats_detected": threats_detected,
            "safe_detected": safe_detected,
            "severity_breakdown": severity_breakdown,
            "module_breakdown": module_breakdown,
            "incidents": all_incidents,
            "warnings": warnings,
            "next_actions": [
                "Review high severity incidents",
                "Open Logs for audit trail",
                "Generate executive report",
            ],
        }
    except Exception as exc:
        raise HTTPException(status_code=500, detail=f"Full SOC demo orchestrator failed: {exc}")


@router.post("/set-interval")
async def set_demo_interval(interval_seconds: int = Query(..., ge=30, le=3600)):
    """
    Set the interval between demo batches.
    
    Args:
        interval_seconds: Time between batches (30-3600 seconds)
    """
    try:
        from services.demo_scheduler import get_demo_scheduler
        
        scheduler = get_demo_scheduler()
        result = scheduler.set_interval(interval_seconds)
        
        return {
            "success": True,
            "message": f"Interval set to {interval_seconds} seconds",
            "interval_seconds": result["interval_seconds"]
        }
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))
