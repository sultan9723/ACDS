from typing import Dict, Any, Optional
from datetime import datetime
from uuid import UUID
import logging

from .models import Incident, Email, IncidentStatus, ExplanationDetails, TimelineEntry
from .database import IncidentDatabase

logger = logging.getLogger(__name__)

class IncidentManager:
    def __init__(self, incident_db: IncidentDatabase):
        self.incident_db = incident_db
        logger.info("IncidentManager initialized.")

    async def create_new_incident(self, email: Email, detection_results: Dict[str, Any]) -> Optional[Incident]:
        explanation_details = None
        if detection_results.get("is_phishing"):
            # If detection is positive, create explanation details
            explanation_details = ExplanationDetails(
                summary="Phishing detection triggered based on analyzed indicators.",
                confidence_score=detection_results.get("confidence_score", 0.0),
                matched_indicators=detection_results.get("matched_indicators", [])
            )
        
        # Create initial timeline entry
        initial_timeline = [
            TimelineEntry(
                event="Email received and processed by Detection Agent",
                details={"email_id": str(email.id), "detection_agent_id": "Initial Detection"}
            )
        ]
        if detection_results.get("is_phishing"):
            initial_timeline.append(
                TimelineEntry(
                    event="Phishing detected",
                    details={"confidence_score": detection_results.get("confidence_score", 0.0)}
                )
            )

        incident = Incident(
            email_id=email.id,
            status=IncidentStatus.PENDING_REVIEW if detection_results.get("is_phishing") else IncidentStatus.NEW,
            detection_agent_id="PhishingDetectionAgent", # This could be dynamic
            explanation_details=explanation_details,
            timeline=initial_timeline,
            timeline_of_events=[entry.model_dump() for entry in initial_timeline],
        )
        
        try:
            await self.incident_db.create_incident(incident)
            logger.info(f"New incident {incident.id} created for email {email.id}.")
            return incident
        except Exception as e:
            logger.error(f"Failed to create incident for email {email.id}: {e}")
            return None

    async def get_incident(self, incident_id: str) -> Optional[Incident]:
        return await self.incident_db.get_incident(incident_id)

    async def update_incident_status(
        self,
        incident_id: str,
        new_status: IncidentStatus,
        actor: Optional[str] = None,
        details: Optional[Dict[str, Any]] = None,
        analyst_id: Optional[str] = None,
    ) -> Optional[Incident]:
        updates = {"status": new_status}
        actor = actor or analyst_id or "system"
        if details is None:
            details = {}
        incident_key = str(incident_id)
        existing_incident = await self.get_incident(incident_key)
        
        # Add timeline entry for status change
        timeline_entry = TimelineEntry(
            event=f"Status updated to {new_status.value}",
            details={
                "actor": actor,
                "previous_status": existing_incident.status.value if existing_incident else "unknown",
                **details,
            }
        )
        
        # Atomically update status and append to timeline
        updated_incident = await self.incident_db.update_incident(
            incident_key,
            {"$set": {"status": new_status.value}, "$push": {"timeline_of_events": timeline_entry.model_dump()}}
        )
        if updated_incident:
            logger.info(f"Incident {incident_id} status updated to {new_status.value} by {actor}.")
        return updated_incident

    async def add_timeline_entry(self, incident_id: str, event: str, details: Optional[Dict[str, Any]] = None) -> Optional[Incident]:
        if details is None:
            details = {}
        timeline_entry = TimelineEntry(event=event, details=details)
        
        # Atomically push to timeline
        updated_incident = await self.incident_db.update_incident(
            incident_id, 
            {"$push": {"timeline": timeline_entry.model_dump()}}
        )
        if updated_incident:
            logger.info(f"Timeline entry added for incident {incident_id}: {event}.")
        return updated_incident

_incident_manager_instance: Optional[IncidentManager] = None

async def get_incident_manager(incident_db: IncidentDatabase) -> IncidentManager:
    global _incident_manager_instance
    if _incident_manager_instance is None:
        _incident_manager_instance = IncidentManager(incident_db)
    return _incident_manager_instance
