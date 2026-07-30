from datetime import datetime
from typing import Dict, Any, List, Optional
from uuid import UUID, uuid4
from enum import Enum
from pydantic import BaseModel, Field, EmailStr

class IncidentStatus(str, Enum):
    NEW = "New"
    PENDING_REVIEW = "Pending Review"
    DETECTED = "Detected"
    INVESTIGATING = "Investigating"
    CONFIRMED_PHISHING = "Confirmed Phishing"
    REMEDIATED = "Remediated"
    CLOSED = "Closed"
    FALSE_POSITIVE = "False Positive"
    FAILED = "Failed" # Added during error handling clarification

class Email(BaseModel):
    id: UUID = Field(default_factory=uuid4)
    raw_content: str
    headers: Dict[str, str] = Field(default_factory=dict)
    sender: EmailStr
    recipients: List[EmailStr] = Field(default_factory=list)
    subject: str
    body: str
    received_at: datetime = Field(default_factory=datetime.utcnow)
    attachments: List[str] = Field(default_factory=list) # Assuming attachments are file paths or IDs for simplicity

class ExplanationDetails(BaseModel):
    summary: str = ""
    confidence_score: float
    matched_indicators: List[str] = Field(default_factory=list)

    def __getitem__(self, key: str) -> Any:
        return getattr(self, key)

class TimelineEntry(BaseModel):
    timestamp: datetime = Field(default_factory=datetime.utcnow)
    event: str
    details: Dict[str, Any] = Field(default_factory=dict)

class Incident(BaseModel):
    id: UUID = Field(default_factory=uuid4)
    email_id: UUID
    status: IncidentStatus = IncidentStatus.NEW
    detection_timestamp: datetime = Field(default_factory=datetime.utcnow)
    detection_agent_id: str
    explanation_details: Optional[ExplanationDetails] = None
    timeline: List[TimelineEntry] = Field(default_factory=list)
    timeline_of_events: List[Dict[str, Any]] = Field(default_factory=list)
    assigned_analyst: Optional[str] = None
    # Add any other relevant details as needed
