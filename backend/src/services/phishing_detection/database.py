import os
from dotenv import load_dotenv
from motor.motor_asyncio import AsyncIOMotorClient
from typing import Dict, Any, List, Optional
from uuid import UUID
import logging

# Load environment variables
load_dotenv()

from .models import Incident, Email, IncidentStatus

# Configure logging
logger = logging.getLogger(__name__)

# Environment variables for MongoDB connection (matching main ACDS settings)
MONGO_URI = os.getenv("MONGO_URI", "mongodb://localhost:27017")
DB_NAME = os.getenv("DB_NAME", "acds")
INCIDENT_COLLECTION = os.getenv("INCIDENT_COLLECTION", "phishing_incidents")

class IncidentDatabase:
    client: Optional[AsyncIOMotorClient] = None
    db: Any = None

    async def connect(self):
        load_dotenv()
        MONGO_URI = os.getenv("MONGO_URI")
        DB_NAME = os.getenv("DB_NAME")

        if not MONGO_URI:
            logger.error("MONGO_URI not found in environment variables. Cannot connect to database.")
            raise ValueError("MONGO_URI environment variable not set.")
        if not DB_NAME:
            logger.error("DB_NAME not found in environment variables. Cannot connect to database.")
            raise ValueError("DB_NAME environment variable not set.")

        self.client = AsyncIOMotorClient(MONGO_URI, uuidRepresentation='standard')
        self.db = self.client[DB_NAME]
        logger.info(f"Connected to MongoDB: {MONGO_URI}, Database: {DB_NAME}")

    async def disconnect(self):
        if self.client:
            self.client.close()
            logger.info("Disconnected from MongoDB.")

    async def create_incident(self, incident: Incident) -> Incident:
        incident_dict = incident.model_dump(by_alias=True)
        # Ensure _id is set for MongoDB, converting UUID to string if necessary
        incident_dict["_id"] = str(incident.id)
        result = await self.db.incidents.insert_one(incident_dict)
        logger.info(f"Created incident with ID: {result.inserted_id}")
        return incident

    async def get_incident(self, incident_id: str) -> Optional[Incident]:
        incident_data = await self.db.incidents.find_one({"_id": incident_id})
        if incident_data:
            # MongoDB uses _id, Pydantic model expects id
            incident_data['id'] = incident_data.pop('_id')
            return Incident(**incident_data)
        return None

    async def update_incident(self, incident_id: str, updates: Dict[str, Any]) -> Optional[Incident]:
        # Ensure UUIDs in updates are converted to string if they are keys or values expected by MongoDB
        # For simplicity, this example assumes updates only contain simple types or dicts that don't need deep UUID conversion
        
        # Prevent direct update of _id
        updates.pop('_id', None) 
        updates.pop('id', None)

        result = await self.db.incidents.update_one(
            {"_id": incident_id},
            {"$set": updates}
        )
        if result.modified_count > 0:
            logger.info(f"Updated incident with ID: {incident_id}")
            return await self.get_incident(incident_id)
        return None

    async def delete_incident(self, incident_id: str) -> bool:
        result = await self.db.incidents.delete_one({"_id": incident_id})
        if result.deleted_count > 0:
            logger.info(f"Deleted incident with ID: {incident_id}")
            return True
        return False

    async def find_incidents(self, query: Dict[str, Any] = None, limit: int = 100, skip: int = 0) -> List[Incident]:
        if query is None:
            query = {}
        
        cursor = self.db.incidents.find(query).skip(skip).limit(limit)
        incidents = []
        async for doc in cursor:
            doc['id'] = doc.pop('_id')
            incidents.append(Incident(**doc))
        return incidents

    async def count_incidents(self, query: Dict[str, Any] = None) -> int:
        if query is None:
            query = {}
        return await self.db.incidents.count_documents(query)

incident_db = IncidentDatabase()

async def get_incident_db() -> IncidentDatabase:
    # Ensure connection is established if not already
    if incident_db.client is None or not incident_db.client.is_connected:
        await incident_db.connect()
    return incident_db
