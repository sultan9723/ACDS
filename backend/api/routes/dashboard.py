"""
Dashboard API Routes
=====================
API endpoints for dashboard data and real-time statistics.
Uses MongoDB database with fallback to mock data.
"""

from datetime import datetime, timezone, timedelta
from typing import Optional
from fastapi import APIRouter, Query
import random
import json
from pathlib import Path

# Import database (optional - fallback to mock data)
try:
    from database.connection import get_collection
    USE_DATABASE = True
except ImportError:
    USE_DATABASE = False
    get_collection = None

router = APIRouter(prefix="/dashboard", tags=["Dashboard"])

PROJECT_ROOT = Path(__file__).resolve().parents[3]
INCIDENTS_DB_PATH = PROJECT_ROOT / "data" / "incidents.json"


def load_json_incidents():
    """Load file-backed incidents when MongoDB is unavailable."""
    if not INCIDENTS_DB_PATH.exists():
        return []
    try:
        with INCIDENTS_DB_PATH.open("r", encoding="utf-8") as handle:
            data = json.load(handle)
        incidents = data.get("incidents", [])
        return incidents if isinstance(incidents, list) else []
    except Exception as exc:
        print(f"Incident JSON load error: {exc}")
        return []


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


@router.get("/stats")
async def get_dashboard_stats():
    """
    Get main dashboard statistics.
    
    Returns key metrics for the dashboard overview.
    """
    # Try to get real stats from database
    db_stats = get_db_stats()
    
    if db_stats:
        return {
            "success": True,
            "stats": {
                "total_threats": db_stats["total_threats"],
                "threats_blocked": db_stats["resolved_threats"],
                "active_threats": db_stats["active_threats"],
                "resolved_today": db_stats["threats_today"],
                "detection_rate": db_stats["detection_rate"],
                "false_positive_rate": 2.1,
                "avg_response_time_ms": 245,
                "emails_scanned_today": db_stats["scans_today"],
                "model_accuracy": 97.2,
                "system_uptime": "99.9%"
            },
            # Also include top-level for frontend compatibility
            "total_threats": db_stats["total_threats"],
            "threats_blocked": db_stats["resolved_threats"],
            "active_threats": db_stats["active_threats"],
            "resolved_today": db_stats["threats_today"],
            "detection_rate": db_stats["detection_rate"],
            "emails_scanned_today": db_stats["scans_today"],
            "model_accuracy": 97.2,
            "data_source": "database"
        }
    
    # Fallback to mock data
    return {
        "success": True,
        "stats": {
            "total_threats": 1247,
            "threats_blocked": 1189,
            "active_threats": 12,
            "resolved_today": 8,
            "detection_rate": 95.3,
            "false_positive_rate": 2.1,
            "avg_response_time_ms": 245,
            "emails_scanned_today": 3421,
            "model_accuracy": 97.2,
            "system_uptime": "99.9%"
        },
        # Also include top-level for frontend compatibility
        "total_threats": 1247,
        "threats_blocked": 1189,
        "active_threats": 12,
        "resolved_today": 8,
        "detection_rate": 95.3,
        "emails_scanned_today": 3421,
        "model_accuracy": 97.2,
        "data_source": "mock"
    }


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
    
    # Fallback to mock data
    activity = []
    for i in range(7):
        date = datetime.now(timezone.utc) - timedelta(days=6 - i)
        activity.append({
            "date": date.strftime("%Y-%m-%d"),
            "threats": random.randint(10, 50),
            "scans": random.randint(200, 500),
            "blocked": random.randint(8, 45)
        })
    return {
        "success": True,
        "activity": activity,
        "data_source": "mock"
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
    if USE_DATABASE and get_collection:
        try:
            logs_col = get_collection("activity_logs")
            
            if logs_col is not None:
                query = {}
                if event_type:
                    query["event"] = event_type
                
                cursor = logs_col.find(query).sort("timestamp", -1).limit(limit)
                logs = []
                for log in cursor:
                    module = str(log.get("module") or ("malware" if "malware" in str(log.get("event", "")).lower() else "phishing")).lower()
                    event = log.get("event", "unknown")
                    is_malware = bool(log.get("is_malware", False))
                    is_phishing = bool(log.get("is_phishing", False))
                    is_threat = bool(log.get("is_threat", is_malware or is_phishing or event in {"threat_detected", "threat_resolved"}))
                    confidence = log.get("confidence", 0)
                    filename = log.get("filename") or log.get("file_name")
                    subject = log.get("email_subject") or filename or "No subject"
                    source_value = log.get("sender") or filename or "Unknown"
                    actions = log.get("actions") or log.get("actions_executed") or ([] if not log.get("action_taken") else [log.get("action_taken")])

                    log_entry = {
                        "id": str(log.get("_id")),
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
                            "actions": actions,
                            "action_taken": log.get("action_taken") or (actions[0] if actions else None),
                            "emails_processed": log.get("emails_processed"),
                            "samples_processed": log.get("samples_processed"),
                            "phishing_detected": log.get("phishing_detected"),
                            "malware_detected": log.get("malware_detected"),
                            "expected": log.get("expected")
                        },
                        "timestamp": log.get("timestamp").isoformat() if log.get("timestamp") else datetime.now(timezone.utc).isoformat()
                    }
                    logs.append(log_entry)
                
                return {
                    "success": True,
                    "logs": logs,
                    "count": len(logs),
                    "data_source": "database"
                }
        except Exception as e:
            print(f"Activity logs error: {e}")
            import traceback
            traceback.print_exc()
    
    incident_logs = []
    for incident in sorted(
        load_json_incidents(),
        key=lambda item: item.get("created_at", ""),
        reverse=True,
    )[:limit]:
        module = str(incident.get("module", "unknown")).lower()
        if event_type and event_type != "ransomware_upload_analyzed":
            continue
        actions = incident.get("actions_taken") or []
        incident_logs.append({
            "id": incident.get("incident_id"),
            "event": "ransomware_upload_analyzed",
            "action_type": "static_executable_analysis",
            "module": module,
            "threat_type": module,
            "message": f"{incident.get('prediction', 'SAFE')} file analysis: {incident.get('filename', 'unknown')}",
            "subject": incident.get("filename"),
            "sender": incident.get("filename"),
            "source": incident.get("filename"),
            "filename": incident.get("filename"),
            "is_threat": incident.get("prediction") == "RANSOMWARE",
            "is_phishing": False,
            "is_malware": False,
            "confidence": incident.get("confidence", 0),
            "severity": incident.get("severity", "LOW"),
            "threat_id": incident.get("incident_id"),
            "actions": actions,
            "action_taken": actions[0] if actions else None,
            "details": {
                "module": module,
                "filename": incident.get("filename"),
                "file_size": incident.get("file_size"),
                "evidence": incident.get("evidence", []),
                "recommended_actions": incident.get("recommended_actions", []),
                "actions": actions,
                "lifecycle_state": incident.get("lifecycle_state"),
            },
            "timestamp": incident.get("created_at") or datetime.now(timezone.utc).isoformat(),
        })

    if incident_logs:
        return {
            "success": True,
            "logs": incident_logs,
            "count": len(incident_logs),
            "data_source": "incidents_json",
        }

    # Fallback - return empty logs (will be populated by demo scheduler)
    return {
        "success": True,
        "logs": [],
        "count": 0,
        "message": "No activity logs yet. Start demo mode to generate logs.",
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

    incidents = [
        incident for incident in load_json_incidents()
        if not severity or incident.get("severity", "").upper() == severity.upper()
    ]
    incidents = sorted(
        incidents,
        key=lambda item: item.get("created_at", ""),
        reverse=True,
    )[:limit]
    if incidents:
        threats = []
        for incident in incidents:
            actions = incident.get("actions_taken") or []
            threats.append({
                "id": incident.get("incident_id"),
                "type": "Ransomware",
                "module": "ransomware",
                "severity": incident.get("severity", "LOW"),
                "confidence": incident.get("confidence", 0),
                "status": incident.get("lifecycle_state", "closed").title(),
                "source": incident.get("filename", "unknown"),
                "subject": incident.get("filename", "Ransomware executable analysis"),
                "is_malware": False,
                "is_phishing": False,
                "is_threat": incident.get("prediction") == "RANSOMWARE",
                "action_taken": actions[0] if actions else None,
                "actions": actions,
                "detected_at": incident.get("created_at") or datetime.now(timezone.utc).isoformat(),
                "description": f"{incident.get('prediction', 'SAFE')} executable analysis: {incident.get('filename', 'unknown')}",
            })

        return {
            "success": True,
            "threats": threats,
            "count": len(threats),
            "data_source": "incidents_json",
        }
    
    # Fallback to mock data
    severities = ["CRITICAL", "HIGH", "MEDIUM", "LOW"]
    threat_types = ["Phishing", "Spear Phishing", "BEC", "Credential Harvesting"]
    statuses = ["Active", "Resolved", "Investigating", "Quarantined"]
    
    threats = []
    for i in range(limit):
        threat_severity = severity or random.choice(severities)
        threats.append({
            "id": f"THR-{1000 + i}",
            "type": random.choice(threat_types),
            "severity": threat_severity,
            "confidence": round(random.uniform(75, 99), 1),
            "status": random.choice(statuses),
            "source": f"suspicious_{i}@phishing-domain.com",
            "detected_at": (datetime.now(timezone.utc) - timedelta(hours=random.randint(0, 48))).isoformat(),
            "description": "Suspicious email with phishing indicators detected"
        })
    
    return {
        "success": True,
        "threats": threats,
        "count": len(threats),
        "data_source": "mock"
    }


@router.get("/threats/timeline")
async def get_threat_timeline(
    days: int = Query(7, le=30)
):
    """
    Get threat detection timeline data for charts.
    """
    timeline = []
    for i in range(days):
        date = datetime.now(timezone.utc) - timedelta(days=days - i - 1)
        timeline.append({
            "date": date.strftime("%Y-%m-%d"),
            "threats_detected": random.randint(10, 50),
            "threats_blocked": random.randint(8, 45),
            "emails_scanned": random.randint(200, 500)
        })
    
    return {
        "success": True,
        "timeline": timeline
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
    
    return {
        "success": True,
        "breakdown": {
            "CRITICAL": 15,
            "HIGH": 47,
            "MEDIUM": 89,
            "LOW": 96
        },
        "data_source": "mock"
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
    
    return {
        "success": True,
        "breakdown": {
            "Phishing": 145,
            "Spear Phishing": 42,
            "Business Email Compromise": 28,
            "Credential Harvesting": 35,
            "Malware Distribution": 18,
            "Other": 12
        },
        "data_source": "mock"
    }


@router.get("/activity/recent")
async def get_recent_activity(limit: int = Query(20, le=100)):
    """
    Get recent system activity log.
    """
    activities = [
        {"type": "scan", "message": "Email scanned - Clean", "timestamp": datetime.now(timezone.utc).isoformat()},
        {"type": "threat", "message": "Phishing email detected and quarantined", "timestamp": datetime.now(timezone.utc).isoformat()},
        {"type": "block", "message": "Sender blocked: malicious@phishing.com", "timestamp": datetime.now(timezone.utc).isoformat()},
        {"type": "report", "message": "Daily threat report generated", "timestamp": datetime.now(timezone.utc).isoformat()},
        {"type": "feedback", "message": "False positive reported and reviewed", "timestamp": datetime.now(timezone.utc).isoformat()},
    ]
    
    return {
        "success": True,
        "activities": activities * (limit // 5 + 1),
        "count": limit
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
    return {
        "success": True,
        "health": {
            "overall_status": "healthy",
            "services": {
                "api_server": {"status": "healthy", "latency_ms": 12},
                "ml_model": {"status": "healthy", "loaded": True},
                "database": {"status": "healthy", "connections": 5},
                "email_scanner": {"status": "healthy", "queue_size": 0}
            },
            "resources": {
                "cpu_usage": 23.5,
                "memory_usage": 45.2,
                "disk_usage": 38.7
            },
            "last_check": datetime.now(timezone.utc).isoformat()
        }
    }
