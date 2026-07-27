"""
Database Models for ACDS
=========================
Pydantic models for request/response validation and MongoDB schemas.
"""

from datetime import datetime
from typing import Optional, List, Dict, Any
from pydantic import BaseModel, Field, EmailStr, field_validator

from core.password_policy import (
    PASSWORD_MAX_LENGTH,
    PASSWORD_MIN_LENGTH,
    validate_password_complexity,
)
from enum import Enum


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
    RESOLVED = "resolved"
    INVESTIGATING = "investigating"
    FALSE_POSITIVE = "false_positive"
    QUARANTINED = "quarantined"


class FeedbackType(str, Enum):
    FALSE_POSITIVE = "false_positive"
    FALSE_NEGATIVE = "false_negative"
    CORRECT_DETECTION = "correct_detection"
    SEVERITY_ADJUSTMENT = "severity_adjustment"
    GENERAL_FEEDBACK = "general_feedback"


class ReportType(str, Enum):
    THREAT_SUMMARY = "threat_summary"
    DETECTION_ANALYSIS = "detection_analysis"
    INCIDENT_LOG = "incident_log"
    PERFORMANCE_METRICS = "performance_metrics"
    EXECUTIVE_SUMMARY = "executive_summary"
    COMPLIANCE_REPORT = "compliance_report"


# =============================================================================
# AUTHENTICATION MODELS
# =============================================================================

class UserBase(BaseModel):
    email: EmailStr
    name: str
    role: str = "user"


class UserCreate(UserBase):
    password: str = Field(..., min_length=PASSWORD_MIN_LENGTH, max_length=PASSWORD_MAX_LENGTH)

    @field_validator("password")
    @classmethod
    def password_meets_complexity(cls, value: str) -> str:
        return validate_password_complexity(value)


class UserLogin(BaseModel):
    email: EmailStr
    password: str = Field(..., min_length=1, max_length=PASSWORD_MAX_LENGTH)


class UserResponse(UserBase):
    id: str
    created_at: datetime
    last_login: Optional[datetime] = None


class TokenResponse(BaseModel):
    access_token: str
    token_type: str = "bearer"
    expires_in: int
    user: UserResponse


# =============================================================================
# EMAIL SCAN MODELS
# =============================================================================

class EmailScanRequest(BaseModel):
    """Request model for scanning an email."""
    content: str = Field(..., description="Email content to analyze")
    sender: Optional[str] = Field(None, description="Email sender address")
    subject: Optional[str] = Field(None, description="Email subject")
    recipient: Optional[str] = Field(None, description="Email recipient")
    headers: Optional[Dict[str, str]] = Field(None, description="Email headers")


class EmailScanBatchRequest(BaseModel):
    """Request model for batch email scanning."""
    emails: List[EmailScanRequest]


class EmailFeatures(BaseModel):
    """Extracted features from an email."""
    url_count: int = 0
    email_count: int = 0
    has_html: bool = False
    urgency_score: int = 0
    suspicious_keywords: List[str] = []
    has_attachments: bool = False


class ScanResult(BaseModel):
    """Result of an email scan."""
    id: str
    timestamp: datetime
    is_phishing: bool
    confidence: float
    severity: ThreatSeverity
    risk_score: float
    features: EmailFeatures
    indicators: List[str]
    recommendation: str
    model_used: bool


class ScanResponse(BaseModel):
    """API response for email scan."""
    success: bool
    result: ScanResult
    processing_time_ms: float


# =============================================================================
# THREAT MODELS
# =============================================================================

class ThreatBase(BaseModel):
    """Base threat model."""
    type: str = "phishing"
    severity: ThreatSeverity
    confidence: float
    source: Optional[str] = None
    target: Optional[str] = None
    description: Optional[str] = None


class ThreatCreate(ThreatBase):
    """Model for creating a new threat."""
    scan_id: Optional[str] = None
    email_content: Optional[str] = None
    sender: Optional[str] = None
    indicators: List[str] = []


class ThreatUpdate(BaseModel):
    """Model for updating a threat."""
    status: Optional[ThreatStatus] = None
    severity: Optional[ThreatSeverity] = None
    notes: Optional[str] = None
    assigned_to: Optional[str] = None


class ThreatResponse(ThreatBase):
    """Response model for a threat."""
    id: str
    status: ThreatStatus
    created_at: datetime
    updated_at: Optional[datetime] = None
    resolved_at: Optional[datetime] = None
    indicators: List[str] = []
    response_actions: List[Dict[str, Any]] = []
    notes: Optional[str] = None
    assigned_to: Optional[str] = None


class ThreatListResponse(BaseModel):
    """Response for listing threats."""
    threats: List[ThreatResponse]
    total: int
    page: int
    page_size: int


# =============================================================================
# FEEDBACK MODELS
# =============================================================================

class FeedbackCreate(BaseModel):
    """Model for creating feedback."""
    scan_id: str
    feedback_type: FeedbackType
    correct_label: Optional[bool] = None
    correct_severity: Optional[ThreatSeverity] = None
    comment: Optional[str] = None
    email_content: Optional[str] = None


class FeedbackResponse(BaseModel):
    """Response model for feedback."""
    feedback_id: str
    scan_id: str
    feedback_type: FeedbackType
    timestamp: datetime
    status: str
    reviewed: bool
    reviewer: Optional[str] = None


class FeedbackReview(BaseModel):
    """Model for reviewing feedback."""
    approved: bool
    review_notes: Optional[str] = None


class FeedbackSummary(BaseModel):
    """Summary of feedback statistics."""
    total: int
    by_type: Dict[str, int]
    by_status: Dict[str, int]
    accuracy_metrics: Dict[str, float]


# =============================================================================
# REPORT MODELS
# =============================================================================

class ReportRequest(BaseModel):
    """Request model for generating a report."""
    report_type: ReportType
    start_date: Optional[datetime] = None
    end_date: Optional[datetime] = None
    include_details: bool = True
    format: str = "json"  # json, pdf, html


class ReportSection(BaseModel):
    """A section of a report."""
    title: str
    content: str
    data: Optional[Dict[str, Any]] = None


class ReportResponse(BaseModel):
    """Response model for a generated report."""
    report_id: str
    report_type: ReportType
    generated_at: datetime
    period: Dict[str, datetime]
    summary: str
    sections: List[ReportSection]
    statistics: Dict[str, Any]
    recommendations: List[str]


# =============================================================================
# RESPONSE ACTION MODELS
# =============================================================================

class ResponseAction(BaseModel):
    """Model for a response action."""
    action: str
    status: str
    executed: bool
    details: str
    timestamp: datetime


class ResponseResult(BaseModel):
    """Result of response actions."""
    response_id: str
    threat_id: str
    timestamp: datetime
    actions_taken: List[ResponseAction]
    actions_pending: List[ResponseAction]
    success: bool
    auto_response: bool
    message: str


# =============================================================================
# DASHBOARD / STATISTICS MODELS
# =============================================================================

class DashboardStats(BaseModel):
    """Dashboard statistics."""
    total_scans: int
    threats_detected: int
    threats_blocked: int
    false_positives: int
    detection_rate: float
    avg_response_time_ms: float
    active_threats: int
    resolved_today: int


class TimeSeriesData(BaseModel):
    """Time series data point."""
    timestamp: datetime
    value: float
    label: Optional[str] = None


class ThreatTrend(BaseModel):
    """Threat trend data."""
    period: str
    data: List[TimeSeriesData]
    change_percent: float


class SystemHealth(BaseModel):
    """System health status."""
    status: str  # healthy, degraded, down
    model_loaded: bool
    database_connected: bool
    last_scan_time: Optional[datetime] = None
    uptime_seconds: int
    version: str


# =============================================================================
# BLOCKED SENDER MODELS
# =============================================================================

class BlockedSender(BaseModel):
    """Blocked sender entry."""
    email: str
    blocked_at: datetime
    reason: Optional[str] = None
    blocked_by: Optional[str] = None


class BlockSenderRequest(BaseModel):
    """Request to block a sender."""
    email: str
    reason: Optional[str] = None


class UnblockSenderRequest(BaseModel):
    """Request to unblock a sender."""
    email: str


# =============================================================================
# QUARANTINE MODELS
# =============================================================================

class QuarantinedFile(BaseModel):
    """Quarantined file entry."""
    filename: str
    original_path: str
    quarantine_path: str
    quarantined_at: datetime
    threat_id: Optional[str] = None
    size_bytes: int


class RestoreRequest(BaseModel):
    """Request to restore a file from quarantine."""
    filename: str
    destination: str


# =============================================================================
# GENERIC API MODELS
# =============================================================================

class APIResponse(BaseModel):
    """Generic API response."""
    success: bool
    message: str
    data: Optional[Any] = None


class ErrorResponse(BaseModel):
    """Error response model."""
    success: bool = False
    error: str
    detail: Optional[str] = None
    code: Optional[int] = None


class PaginationParams(BaseModel):
    """Pagination parameters."""
    page: int = 1
    page_size: int = 20
    sort_by: Optional[str] = None
    sort_order: str = "desc"
