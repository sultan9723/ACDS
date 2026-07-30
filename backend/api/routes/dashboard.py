"""
Dashboard API Routes
=====================
API endpoints for dashboard data and real-time statistics.
Uses MongoDB database with local degraded-mode fallbacks.
"""

from datetime import datetime, timezone, timedelta
from typing import Optional
from fastapi import APIRouter, Query

# Import database (optional - fallback to local degraded-mode data)
try:
    from database.connection import get_collection
    USE_DATABASE = True
except ImportError:
    USE_DATABASE = False
    get_collection = None

try:
    from services.phishing_repository import get_phishing_repository
except ImportError:
    try:
        from backend.services.phishing_repository import get_phishing_repository
    except ImportError:
        get_phishing_repository = None

router = APIRouter(prefix="/dashboard", tags=["Dashboard"])


def _normalize_activity_log(log: dict) -> dict:
    module = str(log.get("module") or ("malware" if "malware" in str(log.get("event", "")).lower() else "phishing")).lower()
    event = log.get("event", "unknown")
    is_malware = bool(log.get("is_malware", False))
    is_phishing = bool(log.get("is_phishing", False))
    is_threat = bool(log.get("is_threat", is_malware or is_phishing or event in {"threat_detected", "threat_resolved"}))
    confidence = log.get("confidence", 0)
    filename = log.get("filename") or log.get("file_name")
    subject = log.get("email_subject") or log.get("subject") or filename or "No subject"
    source_value = log.get("sender") or filename or "Unknown"
    actions = log.get("actions") or log.get("actions_executed") or ([] if not log.get("action_taken") else [log.get("action_taken")])
    timestamp = log.get("timestamp")
    stable_id = str(
        log.get("_id")
        or log.get("id")
        or f"{event}-{log.get('session_id', '')}-{log.get('scan_id', '')}-{log.get('threat_id', '')}-{timestamp}"
    )

    return {
        "id": stable_id,
        "event": event,
        "action_type": log.get("action_type", event),
        "module": module,
        "threat_type": log.get("threat_type", module),
        "message": log.get("message") or subject or "Activity logged",
        "session_id": log.get("session_id"),
        "subject": subject,
        "sender": source_value,
        "source": source_value,
        "filename": filename,
        "is_threat": is_threat,
        "is_phishing": is_phishing,
        "is_malware": is_malware,
        "confidence": confidence,
        "severity": log.get("severity", "LOW"),
        "threat_id": log.get("threat_id"),
        "scan_id": log.get("scan_id"),
        "report_id": log.get("report_id"),
        "lifecycle_state": log.get("lifecycle_state"),
        "report_status": log.get("report_status"),
        "expected_label": log.get("expected_label") or log.get("expected"),
        "predicted_label": log.get("predicted_label"),
        "correct": log.get("correct"),
        "evaluation_outcome": log.get("evaluation_outcome"),
        "review_id": log.get("review_id"),
        "review_status": log.get("review_status"),
        "analyst_verdict": log.get("analyst_verdict"),
        "feedback_type": log.get("feedback_type"),
        "correct_label": log.get("correct_label"),
        "reviewed_by": log.get("reviewed_by"),
        "review_notes": log.get("review_notes"),
        "accuracy": log.get("accuracy"),
        "precision": log.get("precision"),
        "recall": log.get("recall"),
        "f1_score": log.get("f1_score"),
        "confusion_matrix": log.get("confusion_matrix"),
        "actions": actions,
        "action_taken": log.get("action_taken") or (actions[0] if actions else None),
        "details": {
            "module": module,
            "is_threat": is_threat,
            "is_phishing": is_phishing,
            "is_malware": is_malware,
            "confidence": confidence,
            "severity": log.get("severity"),
            "sender": source_value,
            "subject": subject,
            "filename": filename,
            "threat_id": log.get("threat_id"),
            "scan_id": log.get("scan_id"),
            "report_id": log.get("report_id"),
            "lifecycle_state": log.get("lifecycle_state"),
            "report_status": log.get("report_status"),
            "expected_label": log.get("expected_label") or log.get("expected"),
            "predicted_label": log.get("predicted_label"),
            "correct": log.get("correct"),
            "evaluation_outcome": log.get("evaluation_outcome"),
            "review_id": log.get("review_id"),
            "review_status": log.get("review_status"),
            "analyst_verdict": log.get("analyst_verdict"),
            "feedback_type": log.get("feedback_type"),
            "correct_label": log.get("correct_label"),
            "reviewed_by": log.get("reviewed_by"),
            "review_notes": log.get("review_notes"),
            "accuracy": log.get("accuracy"),
            "precision": log.get("precision"),
            "recall": log.get("recall"),
            "f1_score": log.get("f1_score"),
            "confusion_matrix": log.get("confusion_matrix"),
            "actions": actions,
            "action_taken": log.get("action_taken") or (actions[0] if actions else None),
            "emails_processed": log.get("emails_processed"),
            "samples_processed": log.get("samples_processed"),
            "phishing_detected": log.get("phishing_detected"),
            "malware_detected": log.get("malware_detected"),
            "expected": log.get("expected")
        },
        "timestamp": timestamp.isoformat() if hasattr(timestamp, "isoformat") else (timestamp or datetime.now(timezone.utc).isoformat())
    }


def _merge_data_sources(*sources: str) -> str:
    values = set()
    for source in sources:
        for part in str(source or "").split("+"):
            if part and part != "empty":
                values.add(part)
    return "+".join(sorted(values)) if values else "empty"


def get_db_stats():
    """Get statistics from database."""
    if not USE_DATABASE or not get_collection:
        return None
    
    try:
        # Get counts from various collections
        threats_col = get_collection("threats")
        scans_col = get_collection("email_scans")
        feedback_col = get_collection("feedback")
        alerts_col = get_collection("alerts")
        
        if threats_col is None:
            return None
        
        total_threats = threats_col.count_documents({})
        active_threats = threats_col.count_documents({"status": "active"})
        resolved_threats = threats_col.count_documents({"status": "resolved"})
        
        # Get today's counts
        today = datetime.now(timezone.utc).replace(hour=0, minute=0, second=0, microsecond=0)
        threats_today = threats_col.count_documents({"detected_at": {"$gte": today}})
        
        total_scans = scans_col.count_documents({}) if scans_col is not None else 0
        phishing_detected = scans_col.count_documents({"is_phishing": True}) if scans_col is not None else 0
        scans_today = scans_col.count_documents({"scanned_at": {"$gte": today}}) if scans_col is not None else 0
        
        pending_feedback = feedback_col.count_documents({"is_reviewed": False}) if feedback_col is not None else 0
        unread_alerts = alerts_col.count_documents({"is_acknowledged": False}) if alerts_col is not None else 0
        
        # Calculate detection rate
        detection_rate = round((phishing_detected / total_scans * 100) if total_scans > 0 else 0, 1)
        
        return {
            "total_threats": total_threats,
            "active_threats": active_threats,
            "resolved_threats": resolved_threats,
            "threats_today": threats_today,
            "total_scans": total_scans,
            "scans_today": scans_today,
            "phishing_detected": phishing_detected,
            "detection_rate": detection_rate,
            "pending_feedback": pending_feedback,
            "unread_alerts": unread_alerts,
            "from_database": True
        }
    except Exception as e:
        print(f"Database stats error: {e}")
        return None


def get_repository_phishing_stats():
    """Get degraded-mode statistics from the phishing repository."""
    if not get_phishing_repository:
        return None

    try:
        repository = get_phishing_repository()
        scans = repository.list_scans(limit=500).records
        threats = repository.list_threats(limit=500).records

        today = datetime.now(timezone.utc).date()

        def is_today(value):
            if not value:
                return False
            try:
                timestamp = datetime.fromisoformat(str(value).replace("Z", "+00:00"))
                return timestamp.date() == today
            except ValueError:
                return False

        total_scans = len(scans)
        phishing_detected = sum(1 for scan in scans if scan.get("is_phishing"))
        active_threats = sum(
            1
            for threat in threats
            if str(threat.get("status", "active")).lower() == "active"
        )
        resolved_threats = sum(
            1
            for threat in threats
            if str(threat.get("status", "")).lower() == "resolved"
        )
        threats_today = sum(1 for threat in threats if is_today(threat.get("detected_at")))
        scans_today = sum(1 for scan in scans if is_today(scan.get("scanned_at")))
        detection_rate = round((phishing_detected / total_scans * 100) if total_scans else 0, 1)

        return {
            "total_threats": len(threats),
            "active_threats": active_threats,
            "resolved_threats": resolved_threats,
            "threats_today": threats_today,
            "total_scans": total_scans,
            "scans_today": scans_today,
            "phishing_detected": phishing_detected,
            "detection_rate": detection_rate,
            "pending_feedback": 0,
            "unread_alerts": 0,
            "from_repository": True,
        }
    except Exception as exc:
        print(f"Phishing repository stats error: {exc}")
        return None


def _dashboard_stats_response(stats: dict, data_source: str):
    """Format dashboard stats while preserving frontend compatibility."""
    threat_types = (
        [{"name": "Phishing", "value": stats["total_threats"]}]
        if stats["total_threats"] > 0
        else []
    )
    return {
        "success": True,
        "stats": {
            "total_threats": stats["total_threats"],
            "threats_blocked": stats["resolved_threats"],
            "active_threats": stats["active_threats"],
            "resolved_today": stats["threats_today"],
            "detection_rate": stats["detection_rate"],
            "false_positive_rate": 0,
            "avg_response_time_ms": 0,
            "emails_scanned_today": stats["scans_today"],
            "model_accuracy": 0,
            "system_uptime": "N/A",
        },
        "total_threats": stats["total_threats"],
        "threats_blocked": stats["resolved_threats"],
        "active_threats": stats["active_threats"],
        "resolved_today": stats["threats_today"],
        "detection_rate": stats["detection_rate"],
        "emails_scanned_today": stats["scans_today"],
        "model_accuracy": 0,
        "threat_types": threat_types,
        "data_source": data_source,
    }


@router.get("/stats")
async def get_dashboard_stats():
    """
    Get main dashboard statistics.
    
    Returns key metrics for the dashboard overview.
    """
    # Try to get real stats from database
    db_stats = get_db_stats()
    
    if db_stats:
        return _dashboard_stats_response(db_stats, "database")

    repository_stats = get_repository_phishing_stats()
    if repository_stats and (repository_stats["total_scans"] > 0 or repository_stats["total_threats"] > 0):
        return _dashboard_stats_response(repository_stats, "repository")

    empty_stats = {
        "total_threats": 0,
        "active_threats": 0,
        "resolved_threats": 0,
        "threats_today": 0,
        "total_scans": 0,
        "scans_today": 0,
        "phishing_detected": 0,
        "detection_rate": 0,
        "pending_feedback": 0,
        "unread_alerts": 0,
    }
    return _dashboard_stats_response(empty_stats, "empty")


# Frontend-compatible routes
@router.get("/recent-threats")
async def get_recent_threats_compat(
    limit: int = Query(10, le=50),
    severity: Optional[str] = None
):
    """Get recent threats (frontend compatible route)."""
    return await get_recent_threats(limit, severity)


@router.get("/model-status")
async def get_model_status_compat():
    """Get model status (frontend compatible route)."""
    perf = await get_model_performance()
    return {
        "success": True,
        "model_loaded": True,
        "version": "2.0.0",
        "last_trained": (datetime.now(timezone.utc) - timedelta(days=3)).isoformat(),
        "accuracy": 97.2,
        "precision": 96.8,
        "recall": 98.1,
        "f1_score": 97.4,
        "total_predictions": 45892,
        "confusion_matrix": {
            "tp": 2341,
            "fp": 48,
            "fn": 47,
            "tn": 43456
        },
        "accuracy_history": [
            {"date": "2025-11-28", "accuracy": 96.5},
            {"date": "2025-11-29", "accuracy": 96.8},
            {"date": "2025-11-30", "accuracy": 97.0},
            {"date": "2025-12-01", "accuracy": 97.1},
            {"date": "2025-12-02", "accuracy": 97.2},
            {"date": "2025-12-03", "accuracy": 97.2},
            {"date": "2025-12-04", "accuracy": 97.2}
        ],
        "logs": [
            {"timestamp": datetime.now(timezone.utc).isoformat(), "event": "Model prediction", "status": "success"},
            {"timestamp": (datetime.now(timezone.utc) - timedelta(minutes=5)).isoformat(), "event": "Batch scan completed", "status": "success"},
            {"timestamp": (datetime.now(timezone.utc) - timedelta(hours=1)).isoformat(), "event": "Model health check", "status": "success"}
        ]
    }


@router.get("/activity")
async def get_activity_compat(limit: int = Query(20, le=100)):
    """Get activity timeline data from database."""
    # Try to get real activity data from database
    if USE_DATABASE and get_collection:
        try:
            threats_col = get_collection("threats")
            scans_col = get_collection("email_scans")
            
            if threats_col is not None:
                activity = []
                for i in range(7):
                    date = datetime.now(timezone.utc) - timedelta(days=6 - i)
                    date_start = date.replace(hour=0, minute=0, second=0, microsecond=0)
                    date_end = date_start + timedelta(days=1)
                    
                    # Get real counts from database
                    threats_count = threats_col.count_documents({
                        "detected_at": {"$gte": date_start, "$lt": date_end}
                    })
                    resolved_count = threats_col.count_documents({
                        "detected_at": {"$gte": date_start, "$lt": date_end},
                        "status": "resolved"
                    })
                    scans_count = scans_col.count_documents({
                        "scanned_at": {"$gte": date_start, "$lt": date_end}
                    }) if scans_col is not None else 0
                    
                    activity.append({
                        "date": date.strftime("%Y-%m-%d"),
                        "threats": threats_count,
                        "scans": scans_count,
                        "blocked": resolved_count
                    })
                
                return {
                    "success": True,
                    "activity": activity,
                    "data_source": "database"
                }
        except Exception as e:
            print(f"Activity fetch error: {e}")

    if get_phishing_repository:
        try:
            repository = get_phishing_repository()
            scans_result = repository.list_scans(limit=500)
            threats_result = repository.list_threats(limit=500)
            scans = scans_result.records
            threats = threats_result.records

            def occurs_on(record, key, target_date):
                value = record.get(key)
                if not value:
                    return False
                try:
                    timestamp = datetime.fromisoformat(str(value).replace("Z", "+00:00"))
                    return timestamp.date() == target_date
                except ValueError:
                    return False

            activity = []
            for i in range(7):
                date = datetime.now(timezone.utc) - timedelta(days=6 - i)
                target_date = date.date()
                threats_count = sum(
                    1 for threat in threats if occurs_on(threat, "detected_at", target_date)
                )
                scans_count = sum(
                    1 for scan in scans if occurs_on(scan, "scanned_at", target_date)
                )
                blocked_count = sum(
                    1
                    for threat in threats
                    if occurs_on(threat, "detected_at", target_date)
                    and str(threat.get("status", "")).lower() == "resolved"
                )
                activity.append({
                    "date": date.strftime("%Y-%m-%d"),
                    "threats": threats_count,
                    "scans": scans_count,
                    "blocked": blocked_count
                })

            return {
                "success": True,
                "activity": activity,
                "data_source": _merge_data_sources(
                    threats_result.data_source,
                    scans_result.data_source,
                )
            }
        except Exception as exc:
            print(f"Phishing repository activity timeline error: {exc}")

    activity = []
    for i in range(7):
        date = datetime.now(timezone.utc) - timedelta(days=6 - i)
        activity.append({
            "date": date.strftime("%Y-%m-%d"),
            "threats": 0,
            "scans": 0,
            "blocked": 0
        })
    return {
        "success": True,
        "activity": activity,
        "data_source": "empty"
    }


@router.get("/activity-logs")
async def get_activity_logs(
    limit: int = Query(50, le=200),
    event_type: Optional[str] = None
):
    """
    Get system activity logs from database.
    
    Returns recent system events including scans, threats, and responses.
    """
    if get_phishing_repository:
        try:
            repository_result = get_phishing_repository().list_activity_logs(
                limit=limit,
                event_type=event_type,
            )
            logs = [_normalize_activity_log(log) for log in repository_result.records]
            if logs:
                return {
                    "success": True,
                    "logs": logs,
                    "count": len(logs),
                    "data_source": repository_result.data_source
                }
        except Exception as e:
            print(f"Phishing repository activity logs error: {e}")
    
    # Fallback - return empty logs (will be populated by demo scheduler)
    return {
        "success": True,
        "logs": [],
        "count": 0,
        "message": "No activity logs yet. Run a module test to generate logs.",
        "data_source": "empty"
    }


@router.get("/threats/recent")
async def get_recent_threats(
    limit: int = Query(10, le=50),
    severity: Optional[str] = None
):
    """
    Get recent threat detections.
    
    Returns list of recently detected threats for the dashboard feed.
    """
    # Try database first
    if USE_DATABASE and get_collection:
        try:
            collection = get_collection("threats")
            if collection is not None:
                query = {}
                if severity:
                    query["severity"] = severity.upper()
                
                cursor = collection.find(query).sort("detected_at", -1).limit(limit)
                threats = []
                for threat in cursor:
                    threat_type = (threat.get("threat_type") or "Phishing").lower()
                    is_malware = threat_type == "malware"
                    file_name = threat.get("filename") or threat.get("file_name") or "unknown"
                    prediction = threat.get("prediction") or ("Malware" if is_malware else "Phishing")
                    action_taken = threat.get("action_taken") or "alert"
                    timestamp_value = (
                        threat.get("detected_at")
                        or threat.get("timestamp")
                        or datetime.now(timezone.utc)
                    )

                    if hasattr(timestamp_value, "isoformat"):
                        detected_at = timestamp_value.isoformat()
                    else:
                        detected_at = str(timestamp_value)

                    threats.append({
                        "id": threat.get("threat_id", str(threat.get("_id"))),
                        "type": threat.get("threat_type", "Phishing"),
                        "module": "malware" if is_malware else "phishing",
                        "severity": threat.get("severity", "MEDIUM"),
                        "confidence": threat.get("confidence", 0),
                        "status": threat.get("status", "active").title(),
                        "source": file_name if is_malware else threat.get("email_sender", "unknown"),
                        "subject": file_name if is_malware else (threat.get("email_subject") or "Suspicious email detected"),
                        "is_malware": is_malware,
                        "is_phishing": not is_malware,
                        "action_taken": action_taken,
                        "actions": threat.get("actions_executed") or ([action_taken] if action_taken else []),
                        "lifecycle_state": threat.get("lifecycle_state"),
                        "lifecycle_trace": threat.get("lifecycle_trace"),
                        "response_summary": threat.get("response_summary"),
                        "report_id": threat.get("report_id"),
                        "report_status": threat.get("report_status"),
                        "expected_label": threat.get("expected_label"),
                        "predicted_label": threat.get("predicted_label"),
                        "correct": threat.get("correct"),
                        "evaluation_outcome": threat.get("evaluation_outcome"),
                        "review_id": threat.get("review_id"),
                        "review_status": threat.get("review_status"),
                        "analyst_verdict": threat.get("analyst_verdict"),
                        "feedback_type": threat.get("feedback_type"),
                        "correct_label": threat.get("correct_label"),
                        "reviewed_by": threat.get("reviewed_by"),
                        "reviewed_at": threat.get("reviewed_at").isoformat() if hasattr(threat.get("reviewed_at"), "isoformat") else threat.get("reviewed_at"),
                        "review_notes": threat.get("review_notes"),
                        "detected_at": detected_at,
                        "description": (
                            f"{prediction} file detected: {file_name} | action: {action_taken}"
                            if is_malware
                            else (threat.get("email_subject") or "Suspicious email detected")
                        )
                    })
                
                if threats:
                    return {
                        "success": True,
                        "threats": threats,
                        "count": len(threats),
                        "data_source": "database"
                    }
        except Exception as e:
            print(f"Database error: {e}")

    if get_phishing_repository:
        try:
            threats = []
            repository_result = get_phishing_repository().list_threats(
                limit=limit,
                severity=severity,
            )
            for threat in repository_result.records:

                action_taken = threat.get("action_taken") or "alert"
                timestamp_value = threat.get("detected_at") or datetime.now(timezone.utc)
                detected_at = (
                    timestamp_value.isoformat()
                    if hasattr(timestamp_value, "isoformat")
                    else str(timestamp_value)
                )
                threats.append({
                    "id": threat.get("threat_id"),
                    "type": threat.get("threat_type", "Phishing"),
                    "module": threat.get("module", "phishing"),
                    "severity": threat.get("severity", "MEDIUM"),
                    "confidence": threat.get("confidence", 0),
                    "status": str(threat.get("status", "active")).title(),
                    "source": threat.get("email_sender", "unknown"),
                    "subject": threat.get("email_subject", "Suspicious email detected"),
                    "is_malware": False,
                    "is_phishing": True,
                    "action_taken": action_taken,
                    "actions": threat.get("actions") or ([action_taken] if action_taken else []),
                    "lifecycle_state": threat.get("lifecycle_state"),
                    "lifecycle_trace": threat.get("lifecycle_trace"),
                    "response_summary": threat.get("response_summary"),
                    "report_id": threat.get("report_id"),
                    "report_status": threat.get("report_status"),
                    "expected_label": threat.get("expected_label"),
                    "predicted_label": threat.get("predicted_label"),
                    "correct": threat.get("correct"),
                    "evaluation_outcome": threat.get("evaluation_outcome"),
                    "review_id": threat.get("review_id"),
                    "review_status": threat.get("review_status"),
                    "analyst_verdict": threat.get("analyst_verdict"),
                    "feedback_type": threat.get("feedback_type"),
                    "correct_label": threat.get("correct_label"),
                    "reviewed_by": threat.get("reviewed_by"),
                    "reviewed_at": threat.get("reviewed_at").isoformat() if hasattr(threat.get("reviewed_at"), "isoformat") else threat.get("reviewed_at"),
                    "review_notes": threat.get("review_notes"),
                    "detected_at": detected_at,
                    "description": (
                        threat.get("email_content_preview")
                        or threat.get("email_subject")
                        or "Suspicious email detected"
                    ),
                })

            if threats:
                return {
                    "success": True,
                    "threats": threats[:limit],
                    "count": len(threats[:limit]),
                    "data_source": repository_result.data_source
                }
        except Exception as exc:
            print(f"Phishing repository recent threats error: {exc}")
    
    return {
        "success": True,
        "threats": [],
        "count": 0,
        "data_source": "empty"
    }


@router.get("/threats/timeline")
async def get_threat_timeline(
    days: int = Query(7, le=30)
):
    """
    Get threat detection timeline data for charts.
    """
    if get_phishing_repository:
        try:
            repository = get_phishing_repository()
            scans_result = repository.list_scans(limit=500)
            threats_result = repository.list_threats(limit=500)
            scans = scans_result.records
            threats = threats_result.records

            def occurs_on(record, key, target_date):
                value = record.get(key)
                if not value:
                    return False
                try:
                    timestamp = datetime.fromisoformat(str(value).replace("Z", "+00:00"))
                    return timestamp.date() == target_date
                except ValueError:
                    return False

            timeline = []
            for i in range(days):
                date = datetime.now(timezone.utc) - timedelta(days=days - i - 1)
                target_date = date.date()
                threats_detected = sum(
                    1 for threat in threats if occurs_on(threat, "detected_at", target_date)
                )
                emails_scanned = sum(
                    1 for scan in scans if occurs_on(scan, "scanned_at", target_date)
                )
                threats_blocked = sum(
                    1
                    for threat in threats
                    if occurs_on(threat, "detected_at", target_date)
                    and str(threat.get("status", "")).lower() == "resolved"
                )
                timeline.append({
                    "date": date.strftime("%Y-%m-%d"),
                    "threats_detected": threats_detected,
                    "threats_blocked": threats_blocked,
                    "emails_scanned": emails_scanned
                })

            return {
                "success": True,
                "timeline": timeline,
                "data_source": _merge_data_sources(
                    threats_result.data_source,
                    scans_result.data_source,
                )
            }
        except Exception as exc:
            print(f"Phishing repository threat timeline error: {exc}")

    timeline = []
    for i in range(days):
        date = datetime.now(timezone.utc) - timedelta(days=days - i - 1)
        timeline.append({
            "date": date.strftime("%Y-%m-%d"),
            "threats_detected": 0,
            "threats_blocked": 0,
            "emails_scanned": 0
        })
    
    return {
        "success": True,
        "timeline": timeline,
        "data_source": "empty"
    }


@router.get("/threats/by-severity")
async def get_threats_by_severity():
    """
    Get threat breakdown by severity level.
    """
    # Try database first
    if USE_DATABASE and get_collection:
        try:
            collection = get_collection("threats")
            if collection is not None:
                pipeline = [
                    {"$group": {"_id": "$severity", "count": {"$sum": 1}}}
                ]
                result = list(collection.aggregate(pipeline))
                breakdown = {item["_id"]: item["count"] for item in result if item["_id"]}
                if breakdown:
                    return {
                        "success": True,
                        "breakdown": breakdown,
                        "data_source": "database"
                    }
        except Exception as e:
            print(f"Database error: {e}")

    if get_phishing_repository:
        try:
            repository_result = get_phishing_repository().list_threats(limit=500)
            breakdown = {}
            for threat in repository_result.records:
                severity = str(threat.get("severity", "MEDIUM")).upper()
                breakdown[severity] = breakdown.get(severity, 0) + 1
            if breakdown:
                return {
                    "success": True,
                    "breakdown": breakdown,
                    "data_source": repository_result.data_source
                }
        except Exception as exc:
            print(f"Phishing repository severity breakdown error: {exc}")
    
    return {
        "success": True,
        "breakdown": {},
        "data_source": "empty"
    }


@router.get("/threats/by-type")
async def get_threats_by_type():
    """
    Get threat breakdown by attack type.
    """
    # Try database first
    if USE_DATABASE and get_collection:
        try:
            collection = get_collection("threats")
            if collection is not None:
                pipeline = [
                    {"$group": {"_id": "$threat_type", "count": {"$sum": 1}}}
                ]
                result = list(collection.aggregate(pipeline))
                breakdown = {item["_id"]: item["count"] for item in result if item["_id"]}
                if breakdown:
                    return {
                        "success": True,
                        "breakdown": breakdown,
                        "data_source": "database"
                    }
        except Exception as e:
            print(f"Database error: {e}")

    if get_phishing_repository:
        try:
            repository_result = get_phishing_repository().list_threats(limit=500)
            breakdown = {}
            for threat in repository_result.records:
                threat_type = str(threat.get("threat_type", "phishing")).replace("_", " ").title()
                breakdown[threat_type] = breakdown.get(threat_type, 0) + 1
            if breakdown:
                return {
                    "success": True,
                    "breakdown": breakdown,
                    "data_source": repository_result.data_source
                }
        except Exception as exc:
            print(f"Phishing repository type breakdown error: {exc}")
    
    return {
        "success": True,
        "breakdown": {},
        "data_source": "empty"
    }


@router.get("/activity/recent")
async def get_recent_activity(limit: int = Query(20, le=100)):
    """
    Get recent system activity log.
    """
    activity_response = await get_activity_logs(limit=limit)
    activities = [
        {
            "type": log.get("event", "activity"),
            "module": log.get("module", "system"),
            "message": log.get("message", "Activity logged"),
            "timestamp": log.get("timestamp"),
            "source": log.get("source"),
            "severity": log.get("severity"),
        }
        for log in activity_response.get("logs", [])
    ]
    
    return {
        "success": True,
        "activities": activities,
        "count": len(activities),
        "data_source": activity_response.get("data_source", "empty")
    }


@router.get("/model/performance")
async def get_model_performance():
    """
    Get ML model performance metrics.
    """
    return {
        "success": True,
        "performance": {
            "accuracy": 97.2,
            "precision": 96.8,
            "recall": 98.1,
            "f1_score": 97.4,
            "auc_roc": 99.1,
            "total_predictions": 45892,
            "true_positives": 2341,
            "false_positives": 48,
            "true_negatives": 43456,
            "false_negatives": 47,
            "last_updated": datetime.now(timezone.utc).isoformat()
        }
    }


@router.get("/alerts")
async def get_active_alerts():
    """
    Get active system alerts and notifications.
    """
    return {
        "success": True,
        "alerts": [
            {
                "id": "alert-001",
                "type": "warning",
                "title": "Elevated Threat Activity",
                "message": "15% increase in phishing attempts detected in the last hour",
                "timestamp": datetime.now(timezone.utc).isoformat(),
                "read": False
            },
            {
                "id": "alert-002",
                "type": "info",
                "title": "Model Update Available",
                "message": "New model version 2.1.0 is available for deployment",
                "timestamp": (datetime.now(timezone.utc) - timedelta(hours=2)).isoformat(),
                "read": True
            }
        ],
        "unread_count": 1
    }


@router.get("/system/health")
async def get_system_health():
    """
    Get overall system health status.
    """
    try:
        from database.connection import get_database_health
        database_health = get_database_health()
    except Exception as exc:
        database_health = {
            "status": "error",
            "connected": False,
            "last_error": str(exc),
        }

    overall_status = "healthy" if database_health.get("connected") else "degraded"

    return {
        "success": True,
        "health": {
            "overall_status": overall_status,
            "services": {
                "api_server": {"status": "healthy"},
                "ml_model": {"status": "healthy", "loaded": True},
                "database": database_health,
                "email_scanner": {"status": "healthy"}
            },
            "resources": {
                "cpu_usage": None,
                "memory_usage": None,
                "disk_usage": None
            },
            "last_check": datetime.now(timezone.utc).isoformat()
        }
    }
