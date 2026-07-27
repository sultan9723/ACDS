"""
ACDS Database Models
=====================
Pydantic models for MongoDB documents with validation.
"""

from datetime import datetime, timezone
from typing import Optional, List, Dict, Any
from enum import Enum
from pydantic import BaseModel, Field, EmailStr, field_validator
from bson import ObjectId

from core.password_policy import (
    PASSWORD_MAX_LENGTH,
    PASSWORD_MIN_LENGTH,
    validate_password_complexity,
)


# =============================================================================
# ENUMS
# =============================================================================

class ThreatSeverity(str, Enum):
    CRITICAL = "CRITICAL"
    HIGH = "HIGH"
    MEDIUM = "MEDIUM"
    LOW = "LOW"
    INFO = "INFO"


class ThreatStatus(str, Enum):
    ACTIVE = "active"
    INVESTIGATING = "investigating"
    QUARANTINED = "quarantined"
    RESOLVED = "resolved"
    FALSE_POSITIVE = "false_positive"


class ThreatType(str, Enum):
    PHISHING = "phishing"
    SPEAR_PHISHING = "spear_phishing"
    BEC = "bec"  # Business Email Compromise
    CREDENTIAL_HARVESTING = "credential_harvesting"
    MALWARE = "malware"
    SPAM = "spam"
    UNKNOWN = "unknown"


class UserRole(str, Enum):
    ADMIN = "admin"
    ANALYST = "analyst"
    USER = "user"
    VIEWER = "viewer"


class FeedbackType(str, Enum):
    FALSE_POSITIVE = "false_positive"
    FALSE_NEGATIVE = "false_negative"
    CORRECT_DETECTION = "correct_detection"
    SEVERITY_ADJUSTMENT = "severity_adjustment"


class ActionType(str, Enum):
    QUARANTINE = "quarantine_email"
    BLOCK_SENDER = "block_sender"
    DELETE = "delete_email"
    ALERT = "send_alert"
    ESCALATE = "escalate"
    WHITELIST = "whitelist"
    NO_ACTION = "no_action"


# =============================================================================
# HELPER FOR MONGODB ObjectId
# =============================================================================

class PyObjectId(ObjectId):
    @classmethod
    def __get_validators__(cls):
        yield cls.validate

    @classmethod
    def validate(cls, v, info=None):
        if not ObjectId.is_valid(v):
            raise ValueError("Invalid ObjectId")
        return ObjectId(v)

    @classmethod
    def __get_pydantic_json_schema__(cls, field_schema, handler):
        return {"type": "string"}


# =============================================================================
# USER MODEL
# =============================================================================

class User(BaseModel):
    """User account model for authentication."""
    
    id: Optional[str] = Field(default=None, alias="_id")
    email: str = Field(..., description="User email address")
    name: str = Field(..., description="User display name")
    password_hash: str = Field(..., description="Hashed password")
    role: UserRole = Field(default=UserRole.USER)
    is_active: bool = Field(default=True)
    created_at: datetime = Field(default_factory=lambda: datetime.now(timezone.utc))
    last_login: Optional[datetime] = None
    login_count: int = Field(default=0)
    preferences: Dict[str, Any] = Field(default_factory=dict)
    
    class Config:
        populate_by_name = True
        json_encoders = {ObjectId: str, datetime: lambda v: v.isoformat()}


class UserCreate(BaseModel):
    """Schema for creating a new user."""
    email: EmailStr
    name: str = Field(..., min_length=1, max_length=120)
    password: str = Field(..., min_length=PASSWORD_MIN_LENGTH, max_length=PASSWORD_MAX_LENGTH)
    role: UserRole = UserRole.USER

    @field_validator("password")
    @classmethod
    def password_meets_complexity(cls, value: str) -> str:
        return validate_password_complexity(value)


class UserResponse(BaseModel):
    """User response without sensitive data."""
    id: str
    email: str
    name: str
    role: str
    is_active: bool
    created_at: datetime
    last_login: Optional[datetime]


# =============================================================================
# THREAT MODEL
# =============================================================================

class ThreatIndicators(BaseModel):
    """Extracted indicators of compromise."""
    urls: List[str] = Field(default_factory=list)
    domains: List[str] = Field(default_factory=list)
    ip_addresses: List[str] = Field(default_factory=list)
    suspicious_keywords: List[str] = Field(default_factory=list)
    urgency_score: float = Field(default=0.0)


class Threat(BaseModel):
    """Detected threat model."""
    
    id: Optional[str] = Field(default=None, alias="_id")
    threat_id: str = Field(..., description="Unique threat identifier (e.g., THR-1001)")
    
    # Classification
    threat_type: ThreatType = Field(default=ThreatType.PHISHING)
    severity: ThreatSeverity = Field(default=ThreatSeverity.MEDIUM)
    status: ThreatStatus = Field(default=ThreatStatus.ACTIVE)
    confidence: float = Field(..., ge=0, le=100, description="Detection confidence %")
    
    # Email details
    email_subject: Optional[str] = None
    email_sender: Optional[str] = None
    email_recipient: Optional[str] = None
    email_content_preview: Optional[str] = None  # First 200 chars
    email_hash: Optional[str] = None  # For deduplication
    
    # Analysis results
    indicators: ThreatIndicators = Field(default_factory=ThreatIndicators)
    risk_factors: List[str] = Field(default_factory=list)
    
    # Response
    action_taken: Optional[ActionType] = None
    action_timestamp: Optional[datetime] = None
    resolved_by: Optional[str] = None
    resolution_notes: Optional[str] = None
    
    # Timestamps
    detected_at: datetime = Field(default_factory=lambda: datetime.now(timezone.utc))
    updated_at: datetime = Field(default_factory=lambda: datetime.now(timezone.utc))
    
    class Config:
        populate_by_name = True
        json_encoders = {ObjectId: str, datetime: lambda v: v.isoformat()}


class ThreatCreate(BaseModel):
    """Schema for creating a new threat."""
    threat_type: ThreatType = ThreatType.PHISHING
    severity: ThreatSeverity
    confidence: float
    email_subject: Optional[str] = None
    email_sender: Optional[str] = None
    email_recipient: Optional[str] = None
    email_content_preview: Optional[str] = None
    indicators: Optional[ThreatIndicators] = None
    risk_factors: List[str] = Field(default_factory=list)


# =============================================================================
# EMAIL SCAN MODEL
# =============================================================================

class EmailScan(BaseModel):
    """Email scan result model."""
    
    id: Optional[str] = Field(default=None, alias="_id")
    scan_id: str = Field(..., description="Unique scan identifier")
    
    # Input
    email_content: str = Field(..., description="Full email content")
    email_subject: Optional[str] = None
    email_sender: Optional[str] = None
    email_recipient: Optional[str] = None
    
    # Results
    is_phishing: bool = Field(...)
    confidence: float = Field(..., ge=0, le=1)
    risk_level: ThreatSeverity = Field(default=ThreatSeverity.LOW)
    indicators: ThreatIndicators = Field(default_factory=ThreatIndicators)
    
    # Processing
    processing_time_ms: int = Field(default=0)
    model_version: str = Field(default="2.0.0")
    
    # Response taken
    action_taken: Optional[ActionType] = None
    threat_id: Optional[str] = None  # If threat was created
    
    # Timestamps
    scanned_at: datetime = Field(default_factory=lambda: datetime.now(timezone.utc))
    
    class Config:
        populate_by_name = True
        json_encoders = {ObjectId: str, datetime: lambda v: v.isoformat()}


# =============================================================================
# FEEDBACK MODEL
# =============================================================================

class Feedback(BaseModel):
    """User feedback on detection results."""
    
    id: Optional[str] = Field(default=None, alias="_id")
    feedback_id: str = Field(..., description="Unique feedback identifier")
    
    # Reference
    scan_id: str = Field(..., description="Related scan ID")
    threat_id: Optional[str] = None
    
    # Feedback details
    feedback_type: FeedbackType = Field(...)
    original_prediction: bool = Field(..., description="What the model predicted")
    correct_label: Optional[bool] = None  # What it should have been
    suggested_severity: Optional[ThreatSeverity] = None
    comment: Optional[str] = None
    email_content_sample: Optional[str] = None  # For retraining
    
    # Review
    is_reviewed: bool = Field(default=False)
    reviewed_by: Optional[str] = None
    review_timestamp: Optional[datetime] = None
    review_notes: Optional[str] = None
    is_approved: Optional[bool] = None
    
    # Metadata
    submitted_by: Optional[str] = None
    submitted_at: datetime = Field(default_factory=lambda: datetime.now(timezone.utc))
    
    class Config:
        populate_by_name = True
        json_encoders = {ObjectId: str, datetime: lambda v: v.isoformat()}


# =============================================================================
# ALERT MODEL
# =============================================================================

class Alert(BaseModel):
    """Security alert model."""
    
    id: Optional[str] = Field(default=None, alias="_id")
    alert_id: str = Field(..., description="Unique alert identifier")
    
    # Reference
    threat_id: str = Field(..., description="Related threat ID")
    scan_id: Optional[str] = None
    
    # Alert details
    title: str = Field(...)
    description: str = Field(...)
    severity: ThreatSeverity = Field(...)
    
    # Notification
    is_sent: bool = Field(default=False)
    sent_at: Optional[datetime] = None
    recipients: List[str] = Field(default_factory=list)
    
    # Acknowledgment
    is_acknowledged: bool = Field(default=False)
    acknowledged_by: Optional[str] = None
    acknowledged_at: Optional[datetime] = None
    
    # Timestamps
    created_at: datetime = Field(default_factory=lambda: datetime.now(timezone.utc))
    
    class Config:
        populate_by_name = True
        json_encoders = {ObjectId: str, datetime: lambda v: v.isoformat()}


# =============================================================================
# AUDIT LOG MODEL
# =============================================================================

class AuditLog(BaseModel):
    """System audit log for tracking all actions."""
    
    id: Optional[str] = Field(default=None, alias="_id")
    
    # Action
    action: str = Field(..., description="Action performed")
    action_type: str = Field(..., description="Category of action")
    
    # Actor
    user_id: Optional[str] = None
    user_email: Optional[str] = None
    ip_address: Optional[str] = None
    
    # Details
    resource_type: str = Field(..., description="Type of resource affected")
    resource_id: Optional[str] = None
    details: Dict[str, Any] = Field(default_factory=dict)
    
    # Result
    success: bool = Field(default=True)
    error_message: Optional[str] = None
    
    # Timestamp
    timestamp: datetime = Field(default_factory=lambda: datetime.now(timezone.utc))
    
    class Config:
        populate_by_name = True
        json_encoders = {ObjectId: str, datetime: lambda v: v.isoformat()}


# =============================================================================
# REPORTS MODEL
# =============================================================================

class Report(BaseModel):
    """Generated report model."""

    id: Optional[str] = Field(default=None, alias="_id")
    report_id: str = Field(..., description="Unique report identifier")
    report_type: str = Field(..., description="Type of report")
    title: str = Field(default="Untitled Report")
    description: str = Field(default="")

    # Authorship
    generated_by: Optional[str] = None
    format: str = Field(default="json")

    # File reference
    file_path: Optional[str] = None
    file_size_bytes: int = Field(default=0)

    # Date range covered
    period_start: Optional[datetime] = None
    period_end: Optional[datetime] = None

    # Content
    summary: str = Field(default="")
    sections: List[Dict[str, Any]] = Field(default_factory=list)
    statistics: Dict[str, Any] = Field(default_factory=dict)
    recommendations: List[str] = Field(default_factory=list)
    tags: List[str] = Field(default_factory=list)

    # Timestamp
    generated_at: datetime = Field(default_factory=lambda: datetime.now(timezone.utc))

    class Config:
        populate_by_name = True
        json_encoders = {ObjectId: str, datetime: lambda v: v.isoformat()}


# =============================================================================
# BLOCKED SENDER MODEL
# =============================================================================

class BlockedSender(BaseModel):
    """Blocked sender entry model."""

    id: Optional[str] = Field(default=None, alias="_id")
    email: str = Field(..., description="Blocked email address")
    blocked_at: datetime = Field(default_factory=lambda: datetime.now(timezone.utc))
    reason: Optional[str] = None
    blocked_by: Optional[str] = None

    class Config:
        populate_by_name = True
        json_encoders = {ObjectId: str, datetime: lambda v: v.isoformat()}


# =============================================================================
# SYSTEM STATS MODEL
# =============================================================================

class SystemStats(BaseModel):
    """System statistics snapshot."""
    
    id: Optional[str] = Field(default=None, alias="_id")
    
    # Threat metrics
    total_threats: int = 0
    active_threats: int = 0
    resolved_threats: int = 0
    threats_today: int = 0
    
    # Scan metrics
    total_scans: int = 0
    scans_today: int = 0
    phishing_detected: int = 0
    legitimate_detected: int = 0
    
    # Performance
    detection_accuracy: float = 0.0
    false_positive_rate: float = 0.0
    avg_response_time_ms: float = 0.0
    
    # Response metrics
    auto_resolved: int = 0
    manual_resolved: int = 0
    
    # Timestamp
    recorded_at: datetime = Field(default_factory=lambda: datetime.now(timezone.utc))
    period: str = Field(default="daily", description="Stats period (hourly/daily/weekly)")
    
    class Config:
        populate_by_name = True
        json_encoders = {ObjectId: str, datetime: lambda v: v.isoformat()}
