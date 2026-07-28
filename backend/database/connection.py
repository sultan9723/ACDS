"""
ACDS Database Connection
========================
MongoDB connection management for sync and async application paths.
"""

import logging
import os
import time
from datetime import datetime, timezone
from typing import Any, Dict, Optional, Union

from motor.motor_asyncio import AsyncIOMotorClient
from pymongo import MongoClient
from pymongo.errors import PyMongoError

try:
    from config.settings import DB_NAME, MONGO_URI
except ImportError:
    try:
        from backend.config.settings import DB_NAME, MONGO_URI
    except ImportError:
        MONGO_URI = os.getenv("MONGO_URI", "mongodb://localhost:27017")
        DB_NAME = os.getenv("DB_NAME", "acds")


logger = logging.getLogger(__name__)


class Database:
    """
    MongoDB connection manager.

    A MongoDB server can respond to ping even when the configured database is
    unauthorized. Connection setup therefore validates database-level access
    with listCollections before exposing a collection to callers.
    """

    client: Optional[AsyncIOMotorClient] = None
    sync_client: Optional[MongoClient] = None
    db = None
    sync_db = None

    _last_error: Optional[str] = None
    _last_checked_at: Optional[str] = None
    _last_sync_attempt_monotonic: float = 0.0
    _last_async_attempt_monotonic: float = 0.0
    _retry_after_seconds: int = int(os.getenv("MONGO_RETRY_AFTER_SECONDS", "30"))

    @classmethod
    def _utc_now(cls) -> str:
        return datetime.now(timezone.utc).isoformat()

    @classmethod
    def _mark_unavailable(cls, error: Union[Exception, str]) -> None:
        cls._last_error = str(error)
        cls._last_checked_at = cls._utc_now()

    @classmethod
    def _mark_available(cls) -> None:
        cls._last_error = None
        cls._last_checked_at = cls._utc_now()

    @classmethod
    def _can_retry_sync(cls, force: bool = False) -> bool:
        if force or cls._last_sync_attempt_monotonic == 0:
            return True
        return (
            time.monotonic() - cls._last_sync_attempt_monotonic
            >= cls._retry_after_seconds
        )

    @classmethod
    def _can_retry_async(cls, force: bool = False) -> bool:
        if force or cls._last_async_attempt_monotonic == 0:
            return True
        return (
            time.monotonic() - cls._last_async_attempt_monotonic
            >= cls._retry_after_seconds
        )

    @classmethod
    def _close_sync(cls) -> None:
        if cls.sync_client:
            cls.sync_client.close()
        cls.sync_client = None
        cls.sync_db = None

    @classmethod
    def _close_async(cls) -> None:
        if cls.client:
            cls.client.close()
        cls.client = None
        cls.db = None

    @classmethod
    def _validate_sync_database_access(cls) -> None:
        if cls.sync_db is None:
            raise RuntimeError("MongoDB sync database is not initialized")
        cls.sync_client.admin.command("ping")
        cls.sync_db.command("listCollections", 1, nameOnly=True)

    @classmethod
    async def _validate_async_database_access(cls) -> None:
        if cls.db is None:
            raise RuntimeError("MongoDB async database is not initialized")
        await cls.client.admin.command("ping")
        await cls.db.command("listCollections", 1, nameOnly=True)

    @classmethod
    async def connect(cls, force: bool = False) -> bool:
        """
        Initialize and validate async MongoDB access.

        Returns True only when the configured database is reachable and the
        configured credentials can perform a database-level read operation.
        """
        if cls.db is not None and not force:
            return True
        if not cls._can_retry_async(force=force):
            return False

        cls._last_async_attempt_monotonic = time.monotonic()
        cls._close_async()

        try:
            cls.client = AsyncIOMotorClient(MONGO_URI, serverSelectionTimeoutMS=5000)
            cls.db = cls.client[DB_NAME]
            await cls._validate_async_database_access()
            cls._mark_available()
            logger.info("MongoDB async connection established for database '%s'", DB_NAME)
            return True
        except (PyMongoError, RuntimeError) as exc:
            cls._close_async()
            cls._mark_unavailable(exc)
            logger.warning("MongoDB async unavailable: %s", exc)
            return False

    @classmethod
    def connect_sync(cls, force: bool = False) -> bool:
        """
        Initialize and validate sync MongoDB access.

        Returns True only when the configured database is reachable and the
        configured credentials can perform a database-level read operation.
        """
        if cls.sync_db is not None and not force:
            return True
        if not cls._can_retry_sync(force=force):
            return False

        cls._last_sync_attempt_monotonic = time.monotonic()
        cls._close_sync()

        try:
            cls.sync_client = MongoClient(MONGO_URI, serverSelectionTimeoutMS=5000)
            cls.sync_db = cls.sync_client[DB_NAME]
            cls._validate_sync_database_access()
            cls._mark_available()
            logger.info("MongoDB sync connection established for database '%s'", DB_NAME)
            return True
        except (PyMongoError, RuntimeError) as exc:
            cls._close_sync()
            cls._mark_unavailable(exc)
            logger.warning("MongoDB sync unavailable: %s", exc)
            return False

    @classmethod
    async def disconnect(cls):
        """Close MongoDB connections."""
        cls._close_async()
        cls._close_sync()
        logger.info("MongoDB connections closed")

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
        """Check if async database access is currently available."""
        if cls.db is None:
            return await cls.connect()
        try:
            await cls._validate_async_database_access()
            cls._mark_available()
            return True
        except (PyMongoError, RuntimeError) as exc:
            cls._close_async()
            cls._mark_unavailable(exc)
            return False

    @classmethod
    def sync_health(cls, force: bool = False) -> Dict[str, Any]:
        """Return structured sync database health for readiness endpoints."""
        if force or cls.sync_db is None:
            connected = cls.connect_sync(force=force)
        else:
            try:
                cls._validate_sync_database_access()
                cls._mark_available()
                connected = True
            except (PyMongoError, RuntimeError) as exc:
                cls._close_sync()
                cls._mark_unavailable(exc)
                connected = False

        status = "healthy" if connected else "unavailable"
        return {
            "status": status,
            "configured": bool(MONGO_URI),
            "connected": connected,
            "database": DB_NAME,
            "last_checked_at": cls._last_checked_at,
            "last_error": cls._last_error,
            "retry_after_seconds": cls._retry_after_seconds,
        }


db = Database()


def get_collection(name: str):
    """Get a sync collection by name when database access is healthy."""
    if Database.sync_db is None and not Database.connect_sync():
        return None
    return Database.sync_db[name] if Database.sync_db is not None else None


async def get_async_collection(name: str):
    """Get an async collection by name when database access is healthy."""
    if Database.db is None and not await Database.connect():
        return None
    return Database.db[name] if Database.db is not None else None


def get_database_health(force: bool = False) -> Dict[str, Any]:
    """Return structured database health without exposing credentials."""
    return Database.sync_health(force=force)
