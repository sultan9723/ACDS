"""
Threat Detection API Routes
============================
API endpoints for email scanning and threat detection.

Version: 2.0.0 - Orchestrator-based pipeline
Pipeline: Detection → Explainability → Orchestrator → Response
"""

import time
from typing import Optional, List
from datetime import datetime, timezone
from fastapi import APIRouter, HTTPException, Depends, Query
from fastapi.concurrency import run_in_threadpool
from fastapi.responses import JSONResponse
from pydantic import BaseModel, Field

# Define request/response models
class EmailScanRequest(BaseModel):
    content: str = Field(..., description="Email content to scan")
    sender: Optional[str] = Field(None, description="Sender email address")
    subject: Optional[str] = Field(None, description="Email subject line")
    recipient: Optional[str] = Field(None, description="Recipient email address")
    email_id: Optional[str] = Field(None, description="Optional email identifier")

class EmailScanBatchRequest(BaseModel):
    emails: List[EmailScanRequest]

class PhishingTestRunRequest(BaseModel):
    count: int = Field(default=5, ge=1, le=50, description="Number of dataset emails to process")
    include_legitimate: bool = Field(default=True, description="Include legitimate emails in the test run")
    seed: Optional[int] = Field(default=None, ge=0, description="Optional seed for reproducible dataset sampling")

class PhishingReviewRequest(BaseModel):
    scan_id: str = Field(..., min_length=1, description="Scan identifier to review")
    verdict: str = Field(..., description="true_positive, false_positive, false_negative, true_negative, or needs_review")
    analyst: Optional[str] = Field(default=None, description="Analyst identifier")
    notes: Optional[str] = Field(default=None, max_length=2000, description="Optional review notes")

class QuickScanRequest(BaseModel):
    content: str = Field(..., min_length=1, description="Text content to analyze")

# Import services - Orchestrator-based architecture
try:
    from ml.phishing_service import get_phishing_service
    from agents.orchestrator_agent import get_orchestrator_agent
    from agents.detection_agent import get_detection_agent
    from agents.explainability_agent import get_explainability_agent
    from agents.response_agent import get_response_agent
    from services.phishing_lifecycle import build_phishing_lifecycle_trace
    from services.phishing_test_run_service import (
        PhishingTestRunBusyError,
        get_phishing_test_run_service,
    )
    from services.phishing_repository import get_phishing_repository
    from services.phishing_review_service import get_phishing_review_service
except ImportError:
    try:
        from backend.ml.phishing_service import get_phishing_service
        from backend.agents.orchestrator_agent import get_orchestrator_agent
        from backend.agents.detection_agent import get_detection_agent
        from backend.agents.explainability_agent import get_explainability_agent
        from backend.agents.response_agent import get_response_agent
        from backend.services.phishing_lifecycle import build_phishing_lifecycle_trace
        from backend.services.phishing_test_run_service import (
            PhishingTestRunBusyError,
            get_phishing_test_run_service,
        )
        from backend.services.phishing_repository import get_phishing_repository
        from backend.services.phishing_review_service import get_phishing_review_service
    except ImportError:
        get_phishing_service = None
        get_orchestrator_agent = None
        get_detection_agent = None
        get_explainability_agent = None
        get_response_agent = None
        build_phishing_lifecycle_trace = None

        class PhishingTestRunBusyError(RuntimeError):
            pass

        get_phishing_test_run_service = None
        get_phishing_repository = None
        get_phishing_review_service = None

router = APIRouter(prefix="/threats", tags=["Threat Detection"])

# Import database (optional - fallback to in-memory)
try:
    from database.connection import get_collection
    USE_DATABASE = True
except ImportError:
    USE_DATABASE = False
    get_collection = None

# In-memory threat storage (fallback)
import random
_threats_db = {}


def _phishing_error_response(
    status_code: int,
    error_code: str,
    message: str,
    retryable: bool = False,
    context: Optional[dict] = None,
) -> JSONResponse:
    return JSONResponse(
        status_code=status_code,
        content={
            "success": False,
            "error_code": error_code,
            "message": message,
            "detail": message,
            "retryable": retryable,
            "context": context or {},
        },
    )


def _safe_iso(value):
    if hasattr(value, "isoformat"):
        return value.isoformat()
    if value:
        return str(value)
    return datetime.now(timezone.utc).isoformat()


def _normalize_scan_email(scan: dict) -> dict:
    return {
        "id": scan.get("scan_id", str(scan.get("_id"))),
        "scan_id": scan.get("scan_id", str(scan.get("_id"))),
        "threat_id": scan.get("threat_id"),
        "incident_id": scan.get("incident_id"),
        "report_id": scan.get("report_id"),
        "sender": scan.get("email_sender", "Unknown"),
        "subject": scan.get("email_subject", "No subject"),
        "content": scan.get("email_content", "")[:200],
        "prediction": "Phishing" if scan.get("is_phishing") else "Safe",
        "confidence": round(scan.get("confidence", 0) * 100 if scan.get("confidence", 0) <= 1 else scan.get("confidence", 0), 1),
        "severity": scan.get("risk_level", "LOW"),
        "features": scan.get("indicators", {}),
        "evidence": scan.get("evidence", []),
        "expected_label": scan.get("expected_label"),
        "predicted_label": scan.get("predicted_label"),
        "expected_is_phishing": scan.get("expected_is_phishing"),
        "predicted_is_phishing": scan.get("predicted_is_phishing"),
        "correct": scan.get("correct"),
        "evaluation_outcome": scan.get("evaluation_outcome"),
        "evaluation": scan.get("evaluation"),
        "review_id": scan.get("review_id"),
        "review_status": scan.get("review_status"),
        "analyst_verdict": scan.get("analyst_verdict"),
        "feedback_type": scan.get("feedback_type"),
        "correct_label": scan.get("correct_label"),
        "reviewed_by": scan.get("reviewed_by"),
        "reviewed_at": _safe_iso(scan.get("reviewed_at")) if scan.get("reviewed_at") else None,
        "review_notes": scan.get("review_notes"),
        "lifecycle_state": scan.get("lifecycle_state"),
        "lifecycle_trace": scan.get("lifecycle_trace"),
        "response_actions": scan.get("response_actions") or scan.get("actions_taken", []),
        "response_summary": scan.get("response_summary"),
        "report_status": scan.get("report_status"),
        "scanned_at": _safe_iso(scan.get("scanned_at")),
        "data_source": scan.get("data_source", "manual"),
    }


def _normalize_threat(threat: dict) -> dict:
    return {
        "id": threat.get("threat_id", str(threat.get("_id"))),
        "type": threat.get("threat_type", "Phishing"),
        "severity": threat.get("severity", "MEDIUM"),
        "confidence": threat.get("confidence", 0),
        "status": str(threat.get("status", "active")).title(),
        "source": threat.get("email_sender", "unknown"),
        "subject": threat.get("email_subject", "No subject"),
        "detected_at": _safe_iso(threat.get("detected_at")),
        "description": threat.get("email_content_preview") or "Suspicious email detected",
        "module": threat.get("module", "phishing"),
        "action_taken": threat.get("action_taken"),
        "actions": threat.get("response_actions") or threat.get("actions_taken", []),
        "expected_label": threat.get("expected_label"),
        "predicted_label": threat.get("predicted_label"),
        "expected_is_phishing": threat.get("expected_is_phishing"),
        "predicted_is_phishing": threat.get("predicted_is_phishing"),
        "correct": threat.get("correct"),
        "evaluation_outcome": threat.get("evaluation_outcome"),
        "evaluation": threat.get("evaluation"),
        "review_id": threat.get("review_id"),
        "review_status": threat.get("review_status"),
        "analyst_verdict": threat.get("analyst_verdict"),
        "feedback_type": threat.get("feedback_type"),
        "correct_label": threat.get("correct_label"),
        "reviewed_by": threat.get("reviewed_by"),
        "reviewed_at": _safe_iso(threat.get("reviewed_at")) if threat.get("reviewed_at") else None,
        "review_notes": threat.get("review_notes"),
        "lifecycle_state": threat.get("lifecycle_state"),
        "lifecycle_trace": threat.get("lifecycle_trace"),
        "response_summary": threat.get("response_summary"),
        "report_status": threat.get("report_status"),
        "report_id": threat.get("report_id"),
    }


def _build_lifecycle_trace(
    pipeline_result: dict,
    is_phishing: bool,
    actions_taken: Optional[List[str]] = None,
    report_id: Optional[str] = None,
) -> dict:
    if build_phishing_lifecycle_trace is None:
        return {
            "state": pipeline_result.get("lifecycle_state", "reported" if report_id else "resolved"),
            "report_status": "generated" if report_id else ("pending" if is_phishing else "not_required"),
            "actions": actions_taken or [],
            "response_summary": "Lifecycle helper unavailable",
            "response_details": {},
            "stages": [],
        }
    return build_phishing_lifecycle_trace(
        pipeline_result,
        is_phishing=is_phishing,
        actions_taken=actions_taken or [],
        report_id=report_id,
    )


def save_scan_to_database(scan_data: dict) -> Optional[str]:
    """Save scan result through the phishing repository and return scan_id."""
    if not get_phishing_repository:
        return None

    lifecycle_trace = _build_lifecycle_trace(
        scan_data.get("pipeline_result", {}),
        bool(scan_data.get("is_phishing", False)),
        scan_data.get("actions_taken", []),
    )
    scan_doc = {
        "scan_id": f"SCAN-{random.randint(10000, 99999)}",
        "email_content": scan_data.get("content", "")[:500],
        "email_subject": scan_data.get("subject"),
        "email_sender": scan_data.get("sender"),
        "email_recipient": scan_data.get("recipient"),
        "is_phishing": scan_data.get("is_phishing", False),
        "confidence": scan_data.get("confidence", 0),
        "risk_level": scan_data.get("severity", "LOW"),
        "indicators": scan_data.get("indicators", {}),
        "evidence": scan_data.get("evidence", []),
        "incident_id": scan_data.get("incident_id"),
        "lifecycle_state": lifecycle_trace.get("state"),
        "lifecycle_trace": lifecycle_trace,
        "response_actions": lifecycle_trace.get("actions", []),
        "response_summary": lifecycle_trace.get("response_summary"),
        "response_details": lifecycle_trace.get("response_details", {}),
        "report_status": lifecycle_trace.get("report_status"),
        "processing_time_ms": scan_data.get("processing_time_ms", 0),
        "model_version": "2.0.0",
        "scanned_at": datetime.now(timezone.utc)
    }

    try:
        get_phishing_repository().save_scan(scan_doc)
        return scan_doc["scan_id"]
    except Exception as e:
        print(f"Error saving scan: {e}")
    return None


def save_threat_to_database(threat_data: dict) -> Optional[str]:
    """Save detected threat through the phishing repository and return threat_id."""
    if not get_phishing_repository:
        return None

    lifecycle_trace = _build_lifecycle_trace(
        threat_data.get("pipeline_result", {}),
        True,
        threat_data.get("actions_taken", []),
        threat_data.get("report_id"),
    )
    threat_doc = {
        "threat_id": f"THR-{random.randint(1000, 9999)}",
        "incident_id": threat_data.get("incident_id"),
        "scan_id": threat_data.get("scan_id"),
        "module": "phishing",
        "threat_type": threat_data.get("threat_type", "phishing"),
        "severity": threat_data.get("severity", "MEDIUM"),
        "status": "resolved" if threat_data.get("actions_taken") else "active",
        "confidence": threat_data.get("confidence", 0),
        "email_subject": threat_data.get("subject"),
        "email_sender": threat_data.get("sender"),
        "email_recipient": threat_data.get("recipient"),
        "email_content_preview": threat_data.get("content", "")[:200],
        "indicators": threat_data.get("indicators", {}),
        "risk_factors": threat_data.get("risk_factors", []),
        "actions_taken": threat_data.get("actions_taken", []),
        "action_taken": threat_data.get("action_taken"),
        "response_actions": lifecycle_trace.get("actions", []),
        "response_summary": lifecycle_trace.get("response_summary"),
        "response_details": lifecycle_trace.get("response_details", {}),
        "lifecycle_state": lifecycle_trace.get("state"),
        "lifecycle_trace": lifecycle_trace,
        "report_status": lifecycle_trace.get("report_status"),
        "report_id": threat_data.get("report_id"),
        "detected_at": datetime.now(timezone.utc),
        "updated_at": datetime.now(timezone.utc),
        "resolved_at": datetime.now(timezone.utc) if threat_data.get("actions_taken") else None
    }

    try:
        get_phishing_repository().save_threat(threat_doc)
        return threat_doc["threat_id"]
    except Exception as e:
        print(f"Error saving threat: {e}")
    return None


@router.get("/list")
async def list_threats(
    limit: int = Query(50, le=200),
    severity: Optional[str] = None,
    status: Optional[str] = None
):
    """
    List all detected threats.
    
    Returns paginated list of threats with optional filtering.
    """
    if not get_phishing_repository:
        return {
            "success": True,
            "threats": [],
            "total": 0,
            "data_source": "empty",
            "message": "Phishing repository is not available."
        }

    repository_result = get_phishing_repository().list_threats(
        limit=limit,
        severity=severity,
        status=status,
    )
    threats = [_normalize_threat(threat) for threat in repository_result.records]

    if threats:
        return {
            "success": True,
            "threats": threats,
            "total": len(threats),
            "data_source": repository_result.data_source
        }
    
    return {
        "success": True,
        "threats": [],
        "total": 0,
        "data_source": "empty",
        "message": "No persisted threats found."
    }


@router.get("/scans/list")
async def list_scanned_emails(
    limit: int = Query(50, le=200),
    is_phishing: Optional[bool] = None
):
    """
    List all scanned emails from the database.
    
    Returns paginated list of email scans with their results.
    Used by the Email Phishing page to show scan history.
    """
    emails = []
    if not get_phishing_repository:
        return {
            "success": True,
            "emails": [],
            "total": 0,
            "data_source": "empty",
            "message": "Phishing repository is not available."
        }

    repository_result = get_phishing_repository().list_scans(
        limit=limit,
        is_phishing=is_phishing,
    )
    emails = [_normalize_scan_email(scan) for scan in repository_result.records]

    if emails:
        return {
            "success": True,
            "emails": emails,
            "total": len(emails),
            "data_source": repository_result.data_source
        }
    
    return {
        "success": True,
        "emails": [],
        "total": 0,
        "data_source": "empty",
        "message": "No persisted email scans found. Run the Email Phishing test to generate scans."
    }


@router.post("/scan")
async def scan_email(request: EmailScanRequest):
    """
    Scan an email through the full orchestrator pipeline.
    
    Pipeline: Detection → Explainability → Response
    
    Returns comprehensive analysis with:
    - Detection results (is_phishing, confidence, risk_score, severity)
    - Explainability (IOCs, keywords, evidence, explanation)
    - Response actions (if phishing detected)
    - Incident tracking (incident_id for follow-up)
    """
    start_time = time.time()
    
    if not get_orchestrator_agent:
        raise HTTPException(status_code=503, detail="Orchestrator service not available")
    
    try:
        # Get orchestrator and process email
        orchestrator = get_orchestrator_agent()
        result = orchestrator.process_email(request.content, request.email_id)
        
        # Add request context to result
        if request.sender:
            result['sender'] = request.sender
        if request.subject:
            result['subject'] = request.subject
        if request.recipient:
            result['recipient'] = request.recipient
        
        processing_time = (time.time() - start_time) * 1000
        result['processing_time_ms'] = round(processing_time, 2)
        
        # Save to database
        detection = result.get('pipeline_results', {}).get('detection', {})
        explainability = result.get('pipeline_results', {}).get('explainability', {})
        response = result.get('pipeline_results', {}).get('response', {})
        is_phishing = detection.get('is_phishing', False)
        actions_taken = response.get('actions_executed', []) or []
        lifecycle_trace = _build_lifecycle_trace(result, is_phishing, actions_taken)
        result['lifecycle_state'] = lifecycle_trace.get("state")
        result['lifecycle_trace'] = lifecycle_trace
        result['response_summary'] = lifecycle_trace.get("response_summary")
        
        scan_data = {
            "content": request.content,
            "subject": request.subject,
            "sender": request.sender,
            "recipient": request.recipient,
            "is_phishing": is_phishing,
            "confidence": detection.get('confidence', 0),
            "severity": result.get('severity', 'LOW'),
            "processing_time_ms": result['processing_time_ms'],
            "indicators": explainability.get('iocs', {}),
            "evidence": explainability.get('evidence', []),
            "incident_id": result.get('incident_id'),
            "actions_taken": actions_taken,
            "lifecycle_trace": lifecycle_trace,
            "pipeline_result": result,
        }
        
        scan_id = save_scan_to_database(scan_data)
        if scan_id:
            result['scan_id'] = scan_id
        
        # If phishing detected, also save as threat
        if is_phishing:
            threat_data = {
                "threat_type": "phishing",
                "severity": result.get('severity', 'MEDIUM'),
                "confidence": detection.get('confidence', 0),
                "subject": request.subject,
                "sender": request.sender,
                "recipient": request.recipient,
                "content": request.content,
                "indicators": scan_data["indicators"],
                "risk_factors": detection.get('risk_factors', []),
                "action_taken": actions_taken[0] if actions_taken else None,
                "actions_taken": actions_taken,
                "incident_id": result.get('incident_id'),
                "scan_id": scan_id,
                "pipeline_result": result,
            }
            threat_id = save_threat_to_database(threat_data)
            if threat_id:
                result['threat_id'] = threat_id
                if get_phishing_repository and scan_id:
                    get_phishing_repository().update_scan(scan_id, {"threat_id": threat_id})
        
        return {
            "success": True,
            "result": result
        }
    
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))


@router.post("/scan/batch")
async def scan_emails_batch(request: EmailScanBatchRequest):
    """
    Scan multiple emails in batch through the orchestrator pipeline.
    
    Each email goes through: Detection → Explainability → Response
    Returns aggregated results with summary statistics.
    """
    start_time = time.time()
    
    if not get_orchestrator_agent:
        raise HTTPException(status_code=503, detail="Orchestrator service not available")
    
    try:
        orchestrator = get_orchestrator_agent()
        results = []
        
        for email in request.emails:
            result = orchestrator.process_email(email.content, email.email_id)
            if email.sender:
                result['sender'] = email.sender
            if email.subject:
                result['subject'] = email.subject
            results.append(result)
        
        processing_time = (time.time() - start_time) * 1000
        
        # Summary statistics
        phishing_count = sum(
            1 for r in results 
            if r.get('pipeline_results', {}).get('detection', {}).get('is_phishing')
        )
        high_severity = sum(1 for r in results if r.get('severity') == 'HIGH')
        medium_severity = sum(1 for r in results if r.get('severity') == 'MEDIUM')
        
        return {
            "success": True,
            "summary": {
                "total_scanned": len(results),
                "phishing_detected": phishing_count,
                "safe_detected": len(results) - phishing_count,
                "high_severity": high_severity,
                "medium_severity": medium_severity,
                "low_severity": len(results) - high_severity - medium_severity
            },
            "results": results,
            "processing_time_ms": round(processing_time, 2)
        }
    
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))


@router.post("/scan/respond")
async def scan_and_respond(request: EmailScanRequest):
    """
    [DEPRECATED] Use /scan endpoint instead.
    
    The /scan endpoint now includes automatic response actions
    through the orchestrator pipeline.
    """
    # Redirect to main scan endpoint - orchestrator handles response
    return await scan_email(request)


@router.post("/scan/quick")
async def quick_scan(request: QuickScanRequest):
    """
    Quick detection-only scan without full pipeline.
    
    Uses only the Detection Agent for fast classification.
    Good for real-time typing feedback or bulk pre-screening.
    """
    if not get_detection_agent:
        raise HTTPException(status_code=503, detail="Detection agent not available")
    
    try:
        detection_agent = get_detection_agent()
        result = detection_agent.analyze(request.content)
        
        return {
            "success": True,
            "result": {
                "is_phishing": result.get('is_phishing'),
                "confidence": result.get('confidence'),
                "risk_score": result.get('risk_score'),
                "severity": result.get('severity'),
                "model_used": result.get('model_used')
            }
        }
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))


@router.post("/scan/explain")
async def scan_with_explanation(request: EmailScanRequest):
    """
    Scan with detailed explainability output.
    
    Returns Detection + Explainability results without response actions.
    Ideal for analyst review and investigation.
    """
    if not get_detection_agent or not get_explainability_agent:
        raise HTTPException(status_code=503, detail="Agent services not available")
    
    try:
        # Run detection
        detection_agent = get_detection_agent()
        detection_result = detection_agent.analyze(request.content, request.email_id)
        
        # Run explainability
        explainability_agent = get_explainability_agent()
        explain_result = explainability_agent.analyze(
            request.content, 
            detection_result['email_id'],
            detection_result
        )
        
        return {
            "success": True,
            "detection": detection_result,
            "explainability": explain_result
        }
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))


@router.get("/stats")
async def get_detection_stats():
    """
    Get comprehensive pipeline statistics.
    
    Returns metrics from all agents in the pipeline:
    - Orchestrator stats (total incidents, processing times)
    - Detection stats (scans, phishing rate)
    - Response stats (actions taken)
    """
    stats = {
        "orchestrator": {},
        "detection": {},
        "explainability": {},
        "response": {},
        "ml_service": {}
    }
    
    try:
        # Get orchestrator stats
        if get_orchestrator_agent:
            orchestrator = get_orchestrator_agent()
            stats["orchestrator"] = orchestrator.get_stats()
        
        # Get detection stats
        if get_detection_agent:
            detection = get_detection_agent()
            stats["detection"] = detection.get_stats()
        
        # Get explainability stats
        if get_explainability_agent:
            explainability = get_explainability_agent()
            stats["explainability"] = explainability.get_stats()
        
        # Get response stats
        if get_response_agent:
            response = get_response_agent()
            stats["response"] = response.get_stats()
        
        # Get ML service stats
        if get_phishing_service:
            service = get_phishing_service()
            stats["ml_service"] = service.get_stats()
        
        return {
            "success": True,
            "stats": stats
        }
    
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))


@router.get("/model/info")
async def get_model_info():
    """
    Get information about the loaded ML model.
    
    Returns model metadata, training statistics,
    and configuration.
    """
    try:
        service = get_phishing_service()
        return {
            "success": True,
            "model_info": service.get_model_info()
        }
    
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))


@router.get("/blocked-senders")
async def get_blocked_senders():
    """Get list of blocked email senders."""
    if not get_response_agent:
        raise HTTPException(status_code=503, detail="Response agent not available")
    
    response = get_response_agent()
    return {
        "success": True,
        "blocked_senders": response.get_blocked_senders(),
        "count": len(response.get_blocked_senders())
    }


@router.post("/blocked-senders")
async def block_sender(email: str, reason: Optional[str] = None):
    """Add a sender to the block list."""
    if not get_response_agent:
        raise HTTPException(status_code=503, detail="Response agent not available")
    
    response = get_response_agent()
    result = response._block_sender(email, {
        'action': 'block_sender',
        'status': 'pending'
    })
    
    return {
        "success": result.get('executed', False),
        "result": result
    }


@router.delete("/blocked-senders/{email}")
async def unblock_sender(email: str):
    """Remove a sender from the block list."""
    if not get_response_agent:
        raise HTTPException(status_code=503, detail="Response agent not available")
    
    response = get_response_agent()
    success = response.unblock_sender(email)
    
    return {
        "success": success,
        "message": f"Sender {email} {'unblocked' if success else 'not found'}"
    }


@router.get("/quarantine")
async def get_quarantined_files():
    """Get list of quarantined files."""
    if not get_response_agent:
        raise HTTPException(status_code=503, detail="Response agent not available")
    
    response = get_response_agent()
    files = response.get_quarantined_files()
    
    return {
        "success": True,
        "files": files,
        "count": len(files)
    }


@router.post("/quarantine/restore")
async def restore_from_quarantine(filename: str, destination: str):
    """Restore a file from quarantine."""
    if not get_response_agent:
        raise HTTPException(status_code=503, detail="Response agent not available")
    
    response = get_response_agent()
    success = response.restore_from_quarantine(filename, destination)
    
    if not success:
        raise HTTPException(status_code=404, detail="File not found in quarantine")
    
    return {
        "success": True,
        "message": f"File {filename} restored to {destination}"
    }


@router.get("/response-history")
async def get_response_history(limit: int = Query(50, le=200)):
    """Get history of automated responses."""
    if not get_response_agent:
        raise HTTPException(status_code=503, detail="Response agent not available")
    
    response = get_response_agent()
    history = response.get_response_history(limit)
    
    return {
        "success": True,
        "history": history,
        "count": len(history)
    }


@router.post("/phishing/test-run")
async def run_phishing_test_batch(request: PhishingTestRunRequest = PhishingTestRunRequest()):
    """
    Run a phishing module test batch through the full production pipeline.

    This endpoint is intended for the Email Phishing page test-run button. It
    samples dataset emails, runs Detection -> Explainability -> Response through
    the orchestrator, persists scans/threats/activity logs, and generates
    incident reports for detected threats.
    """
    if not get_phishing_test_run_service:
        return _phishing_error_response(
            503,
            "PHISHING_TEST_RUN_SERVICE_UNAVAILABLE",
            "Phishing test-run service is not available",
            retryable=True,
        )

    try:
        service = get_phishing_test_run_service()
        return await run_in_threadpool(
            service.run_test_batch,
            count=request.count,
            include_legitimate=request.include_legitimate,
            seed=request.seed,
        )
    except PhishingTestRunBusyError as exc:
        status_context = {}
        try:
            status_context = get_phishing_test_run_service().get_operational_status()
        except Exception:
            status_context = {}
        return _phishing_error_response(
            409,
            "PHISHING_TEST_RUN_IN_PROGRESS",
            str(exc),
            retryable=True,
            context=status_context,
        )
    except ValueError as exc:
        return _phishing_error_response(
            400,
            "PHISHING_TEST_RUN_INVALID_REQUEST",
            str(exc),
            retryable=False,
        )
    except RuntimeError as exc:
        return _phishing_error_response(
            503,
            "PHISHING_TEST_RUN_UNAVAILABLE",
            str(exc),
            retryable=True,
        )
    except Exception as exc:
        return _phishing_error_response(
            500,
            "PHISHING_TEST_RUN_FAILED",
            str(exc) or "Phishing test run failed unexpectedly",
            retryable=True,
        )


@router.get("/phishing/test-run/status")
async def get_phishing_test_run_status():
    """Return operational state for Email Phishing test runs."""
    if not get_phishing_test_run_service:
        return _phishing_error_response(
            503,
            "PHISHING_TEST_RUN_SERVICE_UNAVAILABLE",
            "Phishing test-run service is not available",
            retryable=True,
        )

    try:
        service = get_phishing_test_run_service()
        status = await run_in_threadpool(service.get_operational_status)
        return {
            "success": True,
            "status": status,
        }
    except Exception as exc:
        return _phishing_error_response(
            500,
            "PHISHING_TEST_RUN_STATUS_FAILED",
            str(exc) or "Unable to read phishing test-run status",
            retryable=True,
        )


@router.get("/phishing/dataset/status")
async def get_phishing_dataset_status():
    """Return metadata for the dataset used by Email Phishing test runs."""
    if not get_phishing_test_run_service:
        raise HTTPException(status_code=503, detail="Phishing test-run service not available")

    try:
        service = get_phishing_test_run_service()
        metadata = await run_in_threadpool(service.get_dataset_metadata)
        return {
            "success": True,
            "dataset": metadata,
        }
    except RuntimeError as exc:
        raise HTTPException(status_code=503, detail=str(exc))
    except Exception as exc:
        raise HTTPException(status_code=500, detail=str(exc))


@router.get("/phishing/review-queue")
async def get_phishing_review_queue(
    limit: int = Query(50, le=200),
    status: Optional[str] = Query(None, description="Filter by review status"),
    include_reviewed: bool = Query(False, description="Include already reviewed records"),
):
    """Return phishing scans that need, or are ready for, analyst review."""
    if not get_phishing_review_service:
        raise HTTPException(status_code=503, detail="Phishing review service not available")

    try:
        service = get_phishing_review_service()
        result = await run_in_threadpool(
            service.list_review_queue,
            limit=limit,
            status=status,
            include_reviewed=include_reviewed,
        )
        return {
            "success": True,
            "items": result["items"],
            "count": len(result["items"]),
            "data_source": result.get("data_source", "empty"),
        }
    except Exception as exc:
        raise HTTPException(status_code=500, detail=str(exc))


@router.post("/phishing/review")
async def submit_phishing_review(request: PhishingReviewRequest):
    """Persist an analyst review verdict for a phishing scan/threat."""
    if not get_phishing_review_service:
        raise HTTPException(status_code=503, detail="Phishing review service not available")

    try:
        service = get_phishing_review_service()
        result = await run_in_threadpool(
            service.submit_review,
            scan_id=request.scan_id,
            verdict=request.verdict,
            analyst=request.analyst,
            notes=request.notes,
        )
        return {
            "success": True,
            "review": result,
        }
    except ValueError as exc:
        raise HTTPException(status_code=400, detail=str(exc))
    except RuntimeError as exc:
        raise HTTPException(status_code=503, detail=str(exc))
    except Exception as exc:
        raise HTTPException(status_code=500, detail=str(exc))


# =============================================================================
# INCIDENT MANAGEMENT ENDPOINTS
# =============================================================================

@router.get("/incidents")
async def get_incidents(limit: int = Query(20, le=100)):
    """
    Get recent incidents from the orchestrator.
    
    Returns incidents tracked during email scanning operations.
    """
    if not get_orchestrator_agent:
        raise HTTPException(status_code=503, detail="Orchestrator not available")
    
    orchestrator = get_orchestrator_agent()
    incidents = orchestrator.get_recent_incidents(limit)
    
    return {
        "success": True,
        "incidents": incidents,
        "count": len(incidents)
    }


@router.get("/incidents/{incident_id}")
async def get_incident(incident_id: str):
    """
    Get details of a specific incident.
    
    Returns full incident record including detection results and actions.
    """
    if not get_orchestrator_agent:
        raise HTTPException(status_code=503, detail="Orchestrator not available")
    
    orchestrator = get_orchestrator_agent()
    incident = orchestrator.get_incident(incident_id)
    
    if not incident:
        raise HTTPException(status_code=404, detail=f"Incident {incident_id} not found")
    
    return {
        "success": True,
        "incident": incident
    }


@router.patch("/incidents/{incident_id}/state")
async def update_incident_state(incident_id: str, new_state: str):
    """
    Update an incident's lifecycle state.
    
    Valid states: detected, analyzing, responded, resolved, reported
    """
    if not get_orchestrator_agent:
        raise HTTPException(status_code=503, detail="Orchestrator not available")
    
    valid_states = ["detected", "analyzing", "responded", "resolved", "reported"]
    if new_state not in valid_states:
        raise HTTPException(
            status_code=400, 
            detail=f"Invalid state. Must be one of: {valid_states}"
        )
    
    orchestrator = get_orchestrator_agent()
    success = orchestrator.update_incident_state(incident_id, new_state)
    
    if not success:
        raise HTTPException(status_code=404, detail=f"Incident {incident_id} not found")
    
    return {
        "success": True,
        "incident_id": incident_id,
        "new_state": new_state
    }


@router.get("/{threat_id}")
async def get_threat_details(threat_id: str):
    """
    Get detailed information about a specific threat.
    """
    # Try database first
    if USE_DATABASE and get_collection:
        try:
            collection = get_collection("threats")
            if collection is not None:
                threat = collection.find_one({"threat_id": threat_id})
                if threat:
                    return {
                        "success": True,
                        "threat": {
                            "id": threat.get("threat_id", str(threat.get("_id"))),
                            "scan_id": threat.get("scan_id"),
                            "threat_id": threat.get("threat_id", str(threat.get("_id"))),
                            "type": threat.get("threat_type", "Phishing"),
                            "severity": threat.get("severity", "MEDIUM"),
                            "confidence": threat.get("confidence", 0),
                            "status": threat.get("status", "active").title(),
                            "source": threat.get("email_sender", "unknown"),
                            "subject": threat.get("email_subject", "No subject"),
                            "recipient": threat.get("email_recipient", "unknown"),
                            "detected_at": threat.get("detected_at").isoformat() if threat.get("detected_at") else None,
                            "content_preview": threat.get("email_content_preview", ""),
                            "indicators": threat.get("indicators", {}),
                            "risk_factors": threat.get("risk_factors", []),
                            "action_taken": threat.get("action_taken"),
                            "actions": threat.get("response_actions") or threat.get("actions_taken", []),
                            "expected_label": threat.get("expected_label"),
                            "predicted_label": threat.get("predicted_label"),
                            "expected_is_phishing": threat.get("expected_is_phishing"),
                            "predicted_is_phishing": threat.get("predicted_is_phishing"),
                            "correct": threat.get("correct"),
                            "evaluation_outcome": threat.get("evaluation_outcome"),
                            "evaluation": threat.get("evaluation"),
                            "review_id": threat.get("review_id"),
                            "review_status": threat.get("review_status"),
                            "analyst_verdict": threat.get("analyst_verdict"),
                            "feedback_type": threat.get("feedback_type"),
                            "correct_label": threat.get("correct_label"),
                            "reviewed_by": threat.get("reviewed_by"),
                            "reviewed_at": _safe_iso(threat.get("reviewed_at")) if threat.get("reviewed_at") else None,
                            "review_notes": threat.get("review_notes"),
                            "lifecycle_state": threat.get("lifecycle_state"),
                            "lifecycle_trace": threat.get("lifecycle_trace"),
                            "response_summary": threat.get("response_summary"),
                            "response_details": threat.get("response_details", {}),
                            "report_id": threat.get("report_id"),
                            "report_status": threat.get("report_status"),
                            "resolved_by": threat.get("resolved_by"),
                            "resolution_notes": threat.get("resolution_notes"),
                            "recommendations": [
                                "Do not click any links in this email",
                                "Report to IT security team",
                                "Change passwords if credentials were entered"
                            ]
                        },
                        "data_source": "database"
                    }
        except Exception as e:
            print(f"Database error: {e}")

    if get_phishing_repository:
        try:
            threat = get_phishing_repository().get_threat(threat_id)
            if threat:
                return {
                    "success": True,
                    "threat": {
                        "id": threat.get("threat_id"),
                        "threat_id": threat.get("threat_id"),
                        "incident_id": threat.get("incident_id"),
                        "type": threat.get("threat_type", "Phishing"),
                        "severity": threat.get("severity", "MEDIUM"),
                        "confidence": threat.get("confidence", 0),
                        "status": str(threat.get("status", "active")).title(),
                        "source": threat.get("email_sender", "unknown"),
                        "subject": threat.get("email_subject", "No subject"),
                        "recipient": threat.get("email_recipient", "unknown"),
                        "detected_at": _safe_iso(threat.get("detected_at")),
                        "content_preview": threat.get("email_content_preview", ""),
                        "indicators": threat.get("indicators", {}),
                        "evidence": threat.get("evidence", []),
                        "risk_factors": threat.get("risk_factors", []),
                        "actions_taken": threat.get("actions_taken", []),
                        "action_taken": threat.get("action_taken"),
                        "actions": threat.get("response_actions") or threat.get("actions_taken", []),
                        "expected_label": threat.get("expected_label"),
                        "predicted_label": threat.get("predicted_label"),
                        "expected_is_phishing": threat.get("expected_is_phishing"),
                        "predicted_is_phishing": threat.get("predicted_is_phishing"),
                        "correct": threat.get("correct"),
                        "evaluation_outcome": threat.get("evaluation_outcome"),
                        "evaluation": threat.get("evaluation"),
                        "review_id": threat.get("review_id"),
                        "review_status": threat.get("review_status"),
                        "analyst_verdict": threat.get("analyst_verdict"),
                        "feedback_type": threat.get("feedback_type"),
                        "correct_label": threat.get("correct_label"),
                        "reviewed_by": threat.get("reviewed_by"),
                        "reviewed_at": _safe_iso(threat.get("reviewed_at")) if threat.get("reviewed_at") else None,
                        "review_notes": threat.get("review_notes"),
                        "lifecycle_state": threat.get("lifecycle_state"),
                        "lifecycle_trace": threat.get("lifecycle_trace"),
                        "response_summary": threat.get("response_summary"),
                        "response_details": threat.get("response_details", {}),
                        "report_id": threat.get("report_id"),
                        "report_status": threat.get("report_status"),
                        "recommendations": [
                            "Do not click any links in this email",
                            "Report to IT security team",
                            "Change passwords if credentials were entered"
                        ]
                    },
                    "data_source": "repository"
                }
        except Exception as e:
            print(f"Phishing repository threat detail error: {e}")

    raise HTTPException(status_code=404, detail=f"Threat {threat_id} was not found")
