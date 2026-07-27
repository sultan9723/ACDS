"""
ACDS Database Connection
=========================
MongoDB connection management using Motor (async MongoDB driver).
"""

from motor.motor_asyncio import AsyncIOMotorClient
from pymongo import MongoClient
from pymongo.errors import ConnectionFailure, ServerSelectionTimeoutError
import os
from typing import Optional

# Import settings with multiple fallback paths
try:
    from config.settings import MONGO_URI, DB_NAME
except ImportError:
    try:
        from backend.config.settings import MONGO_URI, DB_NAME
    except ImportError:
        MONGO_URI = os.getenv("MONGO_URI", "mongodb://localhost:27017")
        DB_NAME = os.getenv("DB_NAME", "acds")


class Database:
    """
    MongoDB Database Connection Manager.
    
    Handles both synchronous (pymongo) and asynchronous (motor) connections.
    """
    
    client: Optional[AsyncIOMotorClient] = None
    sync_client: Optional[MongoClient] = None
    db = None
    sync_db = None
    
    @classmethod
    async def connect(cls) -> bool:
        """
        Initialize async MongoDB connection.
        
        Returns:
            bool: True if connection successful, False otherwise
        """
        try:
            cls.client = AsyncIOMotorClient(MONGO_URI, serverSelectionTimeoutMS=5000)
            cls.db = cls.client[DB_NAME]
            
            # Verify connection
            await cls.client.admin.command('ping')
            print(f"Connected to MongoDB: {DB_NAME}")
            return True
            
        except (ConnectionFailure, ServerSelectionTimeoutError) as e:
            print(f"Warning: MongoDB connection failed: {e}")
            cls.client = None
            cls.db = None
            return False
    
    @classmethod
    def connect_sync(cls) -> bool:
        """
        Initialize synchronous MongoDB connection.
        
        Returns:
            bool: True if connection successful, False otherwise
        """
        try:
            cls.sync_client = MongoClient(MONGO_URI, serverSelectionTimeoutMS=5000)
            cls.sync_db = cls.sync_client[DB_NAME]
            
            # Verify connection
            cls.sync_client.admin.command('ping')
            print(f"Connected to MongoDB (sync): {DB_NAME}")
            return True
            
        except (ConnectionFailure, ServerSelectionTimeoutError) as e:
            print(f"Warning: MongoDB sync connection failed: {e}")
            cls.sync_client = None
            cls.sync_db = None
            return False
    
    @classmethod
    async def disconnect(cls):
        """Close MongoDB connections."""
        if cls.client:
            cls.client.close()
            cls.client = None
            cls.db = None
            print("MongoDB async connection closed")
        
        if cls.sync_client:
            cls.sync_client.close()
            cls.sync_client = None
            cls.sync_db = None
            print("MongoDB sync connection closed")
    
    @classmethod
    def get_db(cls):
        """Get the async database instance."""
        return cls.db
    
    @classmethod
    def get_sync_db(cls):
        """Get the sync database instance."""
        return cls.sync_db
    
    @classmethod
    async def is_connected(cls) -> bool:
        """Check if database is connected."""
        if not cls.client:
            return False
        try:
            await cls.client.admin.command('ping')
            return True
        except:
            return False


# Singleton instance for easy access
db = Database()


# Helper functions for getting collections
def get_collection(name: str):
    """Get a sync collection by name."""
    if Database.sync_db is None:
        Database.connect_sync()
    if Database.sync_db is not None:
        return Database.sync_db[name]
    return None


async def get_async_collection(name: str):
    """Get an async collection by name."""
    if Database.db is None:
        await Database.connect()
    return Database.db[name] if Database.db else None
