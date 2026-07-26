"""
ACDS Database CRUD Operations
==============================
Database operations for all collections.
"""

from datetime import datetime, timezone, timedelta
from typing import List, Optional, Dict, Any
from bson import ObjectId
import logging

# Import with fallback paths
try:
    from config.settings import settings
    from database.connection import get_collection
    from database.models import (
        User, UserCreate, UserResponse,
        Threat, ThreatCreate, ThreatStatus, ThreatSeverity,
        EmailScan,
        Feedback, FeedbackType,
        Alert,
        AuditLog,
        SystemStats
    )
except ImportError:
    try:
        from backend.config.settings import settings
        from backend.database.connection import get_collection
        from backend.database.models import (
            User, UserCreate, UserResponse,
            Threat, ThreatCreate, ThreatStatus, ThreatSeverity,
            EmailScan,
            Feedback, FeedbackType,
            Alert,
            AuditLog,
            SystemStats
        )
    except ImportError:
        settings = None
        get_collection = None

logger = logging.getLogger(__name__)


# =============================================================================
# ID GENERATION HELPERS
# =============================================================================

def _generate_threat_id() -> str:
    """Generate unique threat ID."""
    import random
    return f"THR-{random.randint(1000, 9999)}"


def _generate_scan_id() -> str:
    """Generate unique scan ID."""
    import random
    return f"SCAN-{random.randint(10000, 99999)}"


def _generate_alert_id() -> str:
    """Generate unique alert ID."""
    import random
    return f"ALT-{random.randint(1000, 9999)}"


def _generate_feedback_id() -> str:
    """Generate unique feedback ID."""
    import random
    return f"FB-{random.randint(10000, 99999)}"


# =============================================================================
# USER CRUD
# =============================================================================

class UserCRUD:
    """User database operations."""
    
    def __init__(self):
        self.collection = settings.COLLECTION_USERS
    
    async def create(self, user_data: UserCreate, password_hash: str) -> Optional[Dict]:
        """Create a new user."""
        collection = get_collection(self.collection)
        
        # Check if user exists
        existing = collection.find_one({"email": user_data.email})
        if existing:
            return None
        
        user_doc = {
            "email": user_data.email,
            "name": user_data.name,
            "password_hash": password_hash,
            "role": user_data.role.value,
            "is_active": True,
            "created_at": datetime.now(timezone.utc),
            "last_login": None,
            "login_count": 0,
            "preferences": {}
        }
        
        result = collection.insert_one(user_doc)
        user_doc["_id"] = str(result.inserted_id)
        logger.info(f"Created user: {user_data.email}")
        return user_doc
    
    def get_by_email(self, email: str) -> Optional[Dict]:
        """Get user by email."""
        collection = get_collection(self.collection)
        user = collection.find_one({"email": email})
        if user:
            user["_id"] = str(user["_id"])
        return user
    
    def get_by_id(self, user_id: str) -> Optional[Dict]:
        """Get user by ID."""
        collection = get_collection(self.collection)
        try:
            user = collection.find_one({"_id": ObjectId(user_id)})
            if user:
                user["_id"] = str(user["_id"])
            return user
        except:
            return None
    
    def update_login(self, user_id: str) -> bool:
        """Update user login timestamp."""
        collection = get_collection(self.collection)
        try:
            result = collection.update_one(
                {"_id": ObjectId(user_id)},
                {
                    "$set": {"last_login": datetime.now(timezone.utc)},
                    "$inc": {"login_count": 1}
                }
            )
            return result.modified_count > 0
        except:
            return False
    
    def get_all(self, skip: int = 0, limit: int = 100) -> List[Dict]:
        """Get all users with pagination."""
        collection = get_collection(self.collection)
        users = list(collection.find().skip(skip).limit(limit))
        for user in users:
            user["_id"] = str(user["_id"])
        return users
    
    def count(self) -> int:
        """Get total user count."""
        collection = get_collection(self.collection)
        return collection.count_documents({})


# =============================================================================
# THREAT CRUD
# =============================================================================

class ThreatCRUD:
    """Threat database operations."""
    
    def __init__(self):
        self.collection = settings.COLLECTION_THREATS
    
    def create(self, threat_data: ThreatCreate) -> Dict:
        """Create a new threat."""
        collection = get_collection(self.collection)
        
        threat_doc = {
            "threat_id": _generate_threat_id(),
            "threat_type": threat_data.threat_type.value,
            "severity": threat_data.severity.value,
            "status": ThreatStatus.ACTIVE.value,
            "confidence": threat_data.confidence,
            "email_subject": threat_data.email_subject,
            "email_sender": threat_data.email_sender,
            "email_recipient": threat_data.email_recipient,
            "email_content_preview": threat_data.email_content_preview,
            "email_hash": None,
            "indicators": threat_data.indicators.dict() if threat_data.indicators else {},
            "risk_factors": threat_data.risk_factors,
            "action_taken": None,
            "action_timestamp": None,
            "resolved_by": None,
            "resolution_notes": None,
            "detected_at": datetime.now(timezone.utc),
            "updated_at": datetime.now(timezone.utc)
        }
        
        result = collection.insert_one(threat_doc)
        threat_doc["_id"] = str(result.inserted_id)
        logger.info(f"Created threat: {threat_doc['threat_id']}")
        return threat_doc
    
    def get_by_id(self, threat_id: str) -> Optional[Dict]:
        """Get threat by threat_id."""
        collection = get_collection(self.collection)
        threat = collection.find_one({"threat_id": threat_id})
        if threat:
            threat["_id"] = str(threat["_id"])
        return threat
    
    def get_all(self, skip: int = 0, limit: int = 50, status: Optional[str] = None, severity: Optional[str] = None) -> List[Dict]:
        """Get all threats with filtering."""
        collection = get_collection(self.collection)
        
        query = {}
        if status:
            query["status"] = status
        if severity:
            query["severity"] = severity
        
        threats = list(
            collection.find(query)
            .sort("detected_at", -1)
            .skip(skip)
            .limit(limit)
        )
        
        for threat in threats:
            threat["_id"] = str(threat["_id"])
        return threats
    
    def update_status(self, threat_id: str, status: ThreatStatus, user_id: Optional[str] = None, notes: Optional[str] = None) -> bool:
        """Update threat status."""
        collection = get_collection(self.collection)
        
        update_data = {
            "status": status.value,
            "updated_at": datetime.now(timezone.utc)
        }
        
        if status in [ThreatStatus.RESOLVED, ThreatStatus.FALSE_POSITIVE]:
            update_data["resolved_by"] = user_id
            update_data["resolution_notes"] = notes
        
        result = collection.update_one(
            {"threat_id": threat_id},
            {"$set": update_data}
        )
        return result.modified_count > 0
    
    def set_action(self, threat_id: str, action: str) -> bool:
        """Set action taken on threat."""
        collection = get_collection(self.collection)
        result = collection.update_one(
            {"threat_id": threat_id},
            {"$set": {
                "action_taken": action,
                "action_timestamp": datetime.now(timezone.utc),
                "updated_at": datetime.now(timezone.utc)
            }}
        )
        return result.modified_count > 0
    
    def count(self, status: Optional[str] = None) -> int:
        """Count threats."""
        collection = get_collection(self.collection)
        query = {"status": status} if status else {}
        return collection.count_documents(query)
    
    def count_by_severity(self) -> Dict[str, int]:
        """Get threat counts by severity."""
        collection = get_collection(self.collection)
        pipeline = [
            {"$group": {"_id": "$severity", "count": {"$sum": 1}}}
        ]
        result = list(collection.aggregate(pipeline))
        return {item["_id"]: item["count"] for item in result}
    
    def count_today(self) -> int:
        """Count threats detected today."""
        collection = get_collection(self.collection)
        today = datetime.now(timezone.utc).replace(hour=0, minute=0, second=0, microsecond=0)
        return collection.count_documents({"detected_at": {"$gte": today}})
    
    def get_recent(self, hours: int = 24) -> List[Dict]:
        """Get recent threats."""
        collection = get_collection(self.collection)
        since = datetime.now(timezone.utc) - timedelta(hours=hours)
        threats = list(
            collection.find({"detected_at": {"$gte": since}})
            .sort("detected_at", -1)
        )
        for threat in threats:
            threat["_id"] = str(threat["_id"])
        return threats


# =============================================================================
# EMAIL SCAN CRUD
# =============================================================================

class EmailScanCRUD:
    """Email scan database operations."""
    
    def __init__(self):
        self.collection = settings.COLLECTION_EMAIL_SCANS
    
    def create(self, scan_data: Dict) -> Dict:
        """Create a new scan record."""
        collection = get_collection(self.collection)
        
        scan_doc = {
            "scan_id": _generate_scan_id(),
            "email_content": scan_data.get("email_content", ""),
            "email_subject": scan_data.get("email_subject"),
            "email_sender": scan_data.get("email_sender"),
            "email_recipient": scan_data.get("email_recipient"),
            "is_phishing": scan_data.get("is_phishing", False),
            "confidence": scan_data.get("confidence", 0.0),
            "risk_level": scan_data.get("risk_level", "LOW"),
            "indicators": scan_data.get("indicators", {}),
            "processing_time_ms": scan_data.get("processing_time_ms", 0),
            "model_version": scan_data.get("model_version", "2.0.0"),
            "action_taken": scan_data.get("action_taken"),
            "threat_id": scan_data.get("threat_id"),
            "scanned_at": datetime.now(timezone.utc)
        }
        
        result = collection.insert_one(scan_doc)
        scan_doc["_id"] = str(result.inserted_id)
        logger.info(f"Created scan: {scan_doc['scan_id']}")
        return scan_doc
    
    def get_by_id(self, scan_id: str) -> Optional[Dict]:
        """Get scan by scan_id."""
        collection = get_collection(self.collection)
        scan = collection.find_one({"scan_id": scan_id})
        if scan:
            scan["_id"] = str(scan["_id"])
        return scan
    
    def get_all(self, skip: int = 0, limit: int = 50) -> List[Dict]:
        """Get all scans."""
        collection = get_collection(self.collection)
        scans = list(
            collection.find()
            .sort("scanned_at", -1)
            .skip(skip)
            .limit(limit)
        )
        for scan in scans:
            scan["_id"] = str(scan["_id"])
        return scans
    
    def count(self) -> int:
        """Count total scans."""
        collection = get_collection(self.collection)
        return collection.count_documents({})
    
    def count_phishing(self) -> int:
        """Count phishing detections."""
        collection = get_collection(self.collection)
        return collection.count_documents({"is_phishing": True})
    
    def count_today(self) -> int:
        """Count scans today."""
        collection = get_collection(self.collection)
        today = datetime.now(timezone.utc).replace(hour=0, minute=0, second=0, microsecond=0)
        return collection.count_documents({"scanned_at": {"$gte": today}})


# =============================================================================
# FEEDBACK CRUD
# =============================================================================

class FeedbackCRUD:
    """Feedback database operations."""
    
    def __init__(self):
        self.collection = settings.COLLECTION_FEEDBACK
    
    def create(self, feedback_data: Dict) -> Dict:
        """Create feedback."""
        collection = get_collection(self.collection)
        
        feedback_doc = {
            "feedback_id": _generate_feedback_id(),
            "scan_id": feedback_data.get("scan_id"),
            "threat_id": feedback_data.get("threat_id"),
            "feedback_type": feedback_data.get("feedback_type", "correct_detection"),
            "original_prediction": feedback_data.get("original_prediction"),
            "correct_label": feedback_data.get("correct_label"),
            "suggested_severity": feedback_data.get("suggested_severity"),
            "comment": feedback_data.get("comment"),
            "email_content_sample": feedback_data.get("email_content_sample"),
            "is_reviewed": False,
            "reviewed_by": None,
            "review_timestamp": None,
            "review_notes": None,
            "is_approved": None,
            "submitted_by": feedback_data.get("submitted_by"),
            "submitted_at": datetime.now(timezone.utc)
        }
        
        result = collection.insert_one(feedback_doc)
        feedback_doc["_id"] = str(result.inserted_id)
        logger.info(f"Created feedback: {feedback_doc['feedback_id']}")
        return feedback_doc
    
    def get_all(self, skip: int = 0, limit: int = 50, reviewed: Optional[bool] = None) -> List[Dict]:
        """Get all feedback."""
        collection = get_collection(self.collection)
        
        query = {}
        if reviewed is not None:
            query["is_reviewed"] = reviewed
        
        feedback_list = list(
            collection.find(query)
            .sort("submitted_at", -1)
            .skip(skip)
            .limit(limit)
        )
        
        for feedback in feedback_list:
            feedback["_id"] = str(feedback["_id"])
        return feedback_list
    
    def review(self, feedback_id: str, reviewer_id: str, approved: bool, notes: Optional[str] = None) -> bool:
        """Review feedback."""
        collection = get_collection(self.collection)
        result = collection.update_one(
            {"feedback_id": feedback_id},
            {"$set": {
                "is_reviewed": True,
                "reviewed_by": reviewer_id,
                "review_timestamp": datetime.now(timezone.utc),
                "review_notes": notes,
                "is_approved": approved
            }}
        )
        return result.modified_count > 0
    
    def count(self) -> int:
        """Count all feedback."""
        collection = get_collection(self.collection)
        return collection.count_documents({})
    
    def count_pending(self) -> int:
        """Count pending feedback."""
        collection = get_collection(self.collection)
        return collection.count_documents({"is_reviewed": False})


# =============================================================================
# ALERT CRUD
# =============================================================================

class AlertCRUD:
    """Alert database operations."""
    
    def __init__(self):
        self.collection = settings.COLLECTION_ALERTS
    
    def create(self, alert_data: Dict) -> Dict:
        """Create an alert."""
        collection = get_collection(self.collection)
        
        alert_doc = {
            "alert_id": _generate_alert_id(),
            "threat_id": alert_data.get("threat_id"),
            "scan_id": alert_data.get("scan_id"),
            "title": alert_data.get("title", "Security Alert"),
            "description": alert_data.get("description", ""),
            "severity": alert_data.get("severity", "MEDIUM"),
            "is_sent": alert_data.get("is_sent", False),
            "sent_at": None,
            "recipients": alert_data.get("recipients", []),
            "is_acknowledged": False,
            "acknowledged_by": None,
            "acknowledged_at": None,
            "created_at": datetime.now(timezone.utc)
        }
        
        result = collection.insert_one(alert_doc)
        alert_doc["_id"] = str(result.inserted_id)
        logger.info(f"Created alert: {alert_doc['alert_id']}")
        return alert_doc
    
    def get_all(self, skip: int = 0, limit: int = 50, acknowledged: Optional[bool] = None) -> List[Dict]:
        """Get all alerts."""
        collection = get_collection(self.collection)
        
        query = {}
        if acknowledged is not None:
            query["is_acknowledged"] = acknowledged
        
        alerts = list(
            collection.find(query)
            .sort("created_at", -1)
            .skip(skip)
            .limit(limit)
        )
        
        for alert in alerts:
            alert["_id"] = str(alert["_id"])
        return alerts
    
    def acknowledge(self, alert_id: str, user_id: str) -> bool:
        """Acknowledge alert."""
        collection = get_collection(self.collection)
        result = collection.update_one(
            {"alert_id": alert_id},
            {"$set": {
                "is_acknowledged": True,
                "acknowledged_by": user_id,
                "acknowledged_at": datetime.now(timezone.utc)
            }}
        )
        return result.modified_count > 0
    
    def count_unacknowledged(self) -> int:
        """Count unacknowledged alerts."""
        collection = get_collection(self.collection)
        return collection.count_documents({"is_acknowledged": False})


# =============================================================================
# AUDIT LOG CRUD
# =============================================================================

class AuditLogCRUD:
    """Audit log database operations."""
    
    def __init__(self):
        self.collection = settings.COLLECTION_AUDIT_LOGS
    
    def log(self, action: str, action_type: str, resource_type: str,
            user_id: Optional[str] = None, resource_id: Optional[str] = None,
            details: Optional[Dict] = None, success: bool = True,
            error_message: Optional[str] = None) -> Dict:
        """Create audit log entry."""
        collection = get_collection(self.collection)
        
        log_doc = {
            "action": action,
            "action_type": action_type,
            "user_id": user_id,
            "user_email": None,
            "ip_address": None,
            "resource_type": resource_type,
            "resource_id": resource_id,
            "details": details or {},
            "success": success,
            "error_message": error_message,
            "timestamp": datetime.now(timezone.utc)
        }
        
        result = collection.insert_one(log_doc)
        log_doc["_id"] = str(result.inserted_id)
        return log_doc
    
    def get_recent(self, limit: int = 100) -> List[Dict]:
        """Get recent audit logs."""
        collection = get_collection(self.collection)
        logs = list(
            collection.find()
            .sort("timestamp", -1)
            .limit(limit)
        )
        for log in logs:
            log["_id"] = str(log["_id"])
        return logs
    
    def get_by_user(self, user_id: str, limit: int = 50) -> List[Dict]:
        """Get audit logs by user."""
        collection = get_collection(self.collection)
        logs = list(
            collection.find({"user_id": user_id})
            .sort("timestamp", -1)
            .limit(limit)
        )
        for log in logs:
            log["_id"] = str(log["_id"])
        return logs


# =============================================================================
# SYSTEM STATS CRUD
# =============================================================================

class SystemStatsCRUD:
    """System statistics operations."""
    
    def __init__(self):
        self.collection = settings.COLLECTION_SYSTEM_STATS
    
    def record(self, stats: Dict) -> Dict:
        """Record system stats snapshot."""
        collection = get_collection(self.collection)
        
        stats_doc = {
            "total_threats": stats.get("total_threats", 0),
            "active_threats": stats.get("active_threats", 0),
            "resolved_threats": stats.get("resolved_threats", 0),
            "threats_today": stats.get("threats_today", 0),
            "total_scans": stats.get("total_scans", 0),
            "scans_today": stats.get("scans_today", 0),
            "phishing_detected": stats.get("phishing_detected", 0),
            "legitimate_detected": stats.get("legitimate_detected", 0),
            "detection_accuracy": stats.get("detection_accuracy", 0.0),
            "false_positive_rate": stats.get("false_positive_rate", 0.0),
            "avg_response_time_ms": stats.get("avg_response_time_ms", 0.0),
            "auto_resolved": stats.get("auto_resolved", 0),
            "manual_resolved": stats.get("manual_resolved", 0),
            "recorded_at": datetime.now(timezone.utc),
            "period": stats.get("period", "snapshot")
        }
        
        result = collection.insert_one(stats_doc)
        stats_doc["_id"] = str(result.inserted_id)
        return stats_doc
    
    def get_current(self) -> Dict:
        """Calculate and return current system stats."""
        threat_crud = ThreatCRUD()
        scan_crud = EmailScanCRUD()
        feedback_crud = FeedbackCRUD()
        alert_crud = AlertCRUD()
        
        total_threats = threat_crud.count()
        active_threats = threat_crud.count(status="active")
        resolved_threats = threat_crud.count(status="resolved")
        total_scans = scan_crud.count()
        phishing_detected = scan_crud.count_phishing()
        
        return {
            "total_threats": total_threats,
            "active_threats": active_threats,
            "resolved_threats": resolved_threats,
            "threats_today": threat_crud.count_today(),
            "total_scans": total_scans,
            "scans_today": scan_crud.count_today(),
            "phishing_detected": phishing_detected,
            "legitimate_detected": total_scans - phishing_detected,
            "pending_feedback": feedback_crud.count_pending(),
            "unacknowledged_alerts": alert_crud.count_unacknowledged(),
            "detection_rate": round((phishing_detected / total_scans * 100) if total_scans > 0 else 0, 2),
            "recorded_at": datetime.now(timezone.utc).isoformat()
        }


# =============================================================================
# REPORTS CRUD
# =============================================================================

class ReportsCRUD:
    """Generated reports database operations."""

    def __init__(self):
        self.collection = settings.COLLECTION_REPORTS

    def create(self, report_data: Dict) -> Dict:
        """Store a generated report."""
        collection = get_collection(self.collection)

        report_doc = {
            "report_id": report_data.get("report_id"),
            "report_type": report_data.get("report_type"),
            "title": report_data.get("title", "Untitled Report"),
            "description": report_data.get("description", ""),
            "generated_by": report_data.get("generated_by"),
            "format": report_data.get("format", "json"),
            "file_path": report_data.get("file_path"),
            "file_size_bytes": report_data.get("file_size_bytes", 0),
            "period_start": report_data.get("period_start"),
            "period_end": report_data.get("period_end"),
            "summary": report_data.get("summary", ""),
            "sections": report_data.get("sections", []),
            "statistics": report_data.get("statistics", {}),
            "recommendations": report_data.get("recommendations", []),
            "tags": report_data.get("tags", []),
            "generated_at": report_data.get("generated_at", datetime.now(timezone.utc)),
        }

        result = collection.insert_one(report_doc)
        report_doc["_id"] = str(result.inserted_id)
        logger.info(f"Stored report: {report_doc.get('report_id')}")
        return report_doc

    def get_by_id(self, report_id: str) -> Optional[Dict]:
        """Get a report by its ID."""
        collection = get_collection(self.collection)
        doc = collection.find_one({"report_id": report_id})
        if doc:
            doc["_id"] = str(doc["_id"])
        return doc

    def get_all(self, skip: int = 0, limit: int = 50,
                report_type: Optional[str] = None) -> List[Dict]:
        """List reports with optional type filter."""
        collection = get_collection(self.collection)
        query = {}
        if report_type:
            query["report_type"] = report_type

        docs = list(
            collection.find(query)
            .sort("generated_at", -1)
            .skip(skip)
            .limit(limit)
        )
        for d in docs:
            d["_id"] = str(d["_id"])
        return docs

    def delete(self, report_id: str) -> bool:
        """Delete a report by ID."""
        collection = get_collection(self.collection)
        result = collection.delete_one({"report_id": report_id})
        return result.deleted_count > 0

    def count(self, report_type: Optional[str] = None) -> int:
        """Count reports."""
        collection = get_collection(self.collection)
        query = {}
        if report_type:
            query["report_type"] = report_type
        return collection.count_documents(query)


# =============================================================================
# BLOCKED SENDERS CRUD
# =============================================================================

class BlockedSendersCRUD:
    """Blocked senders database operations."""

    def __init__(self):
        self.collection = settings.COLLECTION_BLOCKED_SENDERS

    def block(self, email: str, reason: Optional[str] = None,
              blocked_by: Optional[str] = None) -> Optional[Dict]:
        """Block a sender."""
        collection = get_collection(self.collection)

        existing = collection.find_one({"email": email})
        if existing:
            return None

        doc = {
            "email": email,
            "blocked_at": datetime.now(timezone.utc),
            "reason": reason,
            "blocked_by": blocked_by,
        }
        result = collection.insert_one(doc)
        doc["_id"] = str(result.inserted_id)
        logger.info(f"Blocked sender: {email}")
        return doc

    def unblock(self, email: str) -> bool:
        """Remove a sender block."""
        collection = get_collection(self.collection)
        result = collection.delete_one({"email": email})
        return result.deleted_count > 0

    def is_blocked(self, email: str) -> bool:
        """Check if a sender is blocked."""
        collection = get_collection(self.collection)
        return collection.find_one({"email": email}) is not None

    def get_all(self, skip: int = 0, limit: int = 100) -> List[Dict]:
        """List all blocked senders."""
        collection = get_collection(self.collection)
        docs = list(
            collection.find()
            .sort("blocked_at", -1)
            .skip(skip)
            .limit(limit)
        )
        for d in docs:
            d["_id"] = str(d["_id"])
        return docs

    def count(self) -> int:
        """Count blocked senders."""
        collection = get_collection(self.collection)
        return collection.count_documents({})


# =============================================================================
# SINGLETON INSTANCES
# =============================================================================

user_crud = UserCRUD()
threat_crud = ThreatCRUD()
email_scan_crud = EmailScanCRUD()
feedback_crud = FeedbackCRUD()
alert_crud = AlertCRUD()
audit_log_crud = AuditLogCRUD()
system_stats_crud = SystemStatsCRUD()
reports_crud = ReportsCRUD()
blocked_senders_crud = BlockedSendersCRUD()
