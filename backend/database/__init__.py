"""
ACDS Database Module
=====================
MongoDB integration for the ACDS platform.
"""

# Use relative imports for internal module access
try:
    from database.connection import Database, db, get_collection, get_async_collection
    from database.models import (
        User, UserCreate, UserResponse,
        Threat, ThreatCreate, ThreatStatus, ThreatSeverity, ThreatType, ThreatIndicators,
        EmailScan,
        Feedback, FeedbackType,
        Alert,
        AuditLog,
        SystemStats,
        UserRole, ActionType
    )
    from database.crud import (
        user_crud, threat_crud, email_scan_crud,
        feedback_crud, alert_crud, audit_log_crud, system_stats_crud,
        reports_crud, blocked_senders_crud
    )
except ImportError:
    # Fallback to backend-prefixed imports
    try:
        from backend.database.connection import Database, db, get_collection, get_async_collection
        from backend.database.models import (
            User, UserCreate, UserResponse,
            Threat, ThreatCreate, ThreatStatus, ThreatSeverity, ThreatType, ThreatIndicators,
            EmailScan,
            Feedback, FeedbackType,
            Alert,
            AuditLog,
            SystemStats,
            UserRole, ActionType
        )
        from backend.database.crud import (
            user_crud, threat_crud, email_scan_crud,
            feedback_crud, alert_crud, audit_log_crud, system_stats_crud,
            reports_crud, blocked_senders_crud
        )
    except ImportError:
        # Module not fully initialized
        Database = None
        db = None
        get_collection = None
        get_async_collection = None

__all__ = [
    # Connection
    "Database", "db", "get_collection", "get_async_collection",
    # Models
    "User", "UserCreate", "UserResponse",
    "Threat", "ThreatCreate", "ThreatStatus", "ThreatSeverity", "ThreatType", "ThreatIndicators",
    "EmailScan", "Feedback", "FeedbackType", "Alert", "AuditLog", "SystemStats",
    "UserRole", "ActionType",
    # CRUD
    "user_crud", "threat_crud", "email_scan_crud",
    "feedback_crud", "alert_crud", "audit_log_crud", "system_stats_crud",
    "reports_crud", "blocked_senders_crud"
]
