"""
Migration Manager
==================
Discovers and applies database migrations in order.

Tracks applied migrations in a `_migrations` collection so each
migration runs exactly once.
"""

import importlib
import logging
import pkgutil
from datetime import datetime, timezone
from typing import List

from database.connection import Database, get_collection, get_async_collection
from database.migrations.base import Migration

logger = logging.getLogger(__name__)

MIGRATIONS_COLLECTION = "_migrations"


def _applied_versions() -> List[str]:
    """Return list of already-applied migration version strings."""
    col = get_collection(MIGRATIONS_COLLECTION)
    if col is None:
        return []
    docs = col.find().sort("applied_at", 1)
    return [d["version"] for d in docs]


def _discover_migrations() -> List[Migration]:
    """Discover all migration classes in the versions package."""
    migrations = []

    try:
        package = importlib.import_module("database.migrations.versions")
    except ImportError:
        try:
            package = importlib.import_module("backend.database.migrations.versions")
        except ImportError:
            logger.error("Could not find migrations.versions package")
            return []

    for importer, modname, ispkg in pkgutil.iter_modules(package.__path__):
        if ispkg or not modname.startswith("v"):
            continue
        try:
            mod = importlib.import_module(f"{package.__name__}.{modname}")
        except Exception as e:
            logger.error("Failed to import migration %s: %s", modname, e)
            continue

        for name in dir(mod):
            obj = getattr(mod, name)
            if isinstance(obj, type) and issubclass(obj, Migration) and obj is not Migration:
                instance = obj()
                migrations.append(instance)
                break

    migrations.sort(key=lambda m: m.version)
    return migrations


def run_migrations() -> int:
    """
    Run all pending migrations synchronously.

    Returns:
        int: Number of migrations applied (0 if none).
    """
    if Database.sync_db is None:
        if not Database.connect_sync():
            logger.warning("Cannot run migrations: database not connected")
            return 0

    db = Database.sync_db
    applied = _applied_versions()
    migrations = _discover_migrations()
    count = 0

    for migration in migrations:
        if migration.version in applied:
            logger.debug("Migration %s already applied, skipping", migration.version)
            continue

        logger.info("Applying migration %s: %s", migration.version, migration.description)
        try:
            success = migration.up(db)
            if success:
                db[MIGRATIONS_COLLECTION].insert_one({
                    "version": migration.version,
                    "description": migration.description,
                    "applied_at": datetime.now(timezone.utc),
                })
                count += 1
                logger.info("Migration %s applied successfully", migration.version)
            else:
                logger.error("Migration %s failed", migration.version)
                return count
        except Exception as e:
            logger.error("Migration %s failed with error: %s", migration.version, e)
            return count

    return count


async def run_migrations_async() -> int:
    """
    Run all pending migrations asynchronously.

    Returns:
        int: Number of migrations applied (0 if none).
    """
    if Database.db is None:
        if not await Database.connect():
            logger.warning("Cannot run migrations: database not connected")
            return 0

    col = await get_async_collection(MIGRATIONS_COLLECTION)
    applied = []
    if col is not None:
        cursor = col.find().sort("applied_at", 1)
        async for doc in cursor:
            applied.append(doc["version"])

    migrations = _discover_migrations()
    count = 0

    for migration in migrations:
        if migration.version in applied:
            logger.debug("Migration %s already applied, skipping", migration.version)
            continue

        logger.info("Applying migration %s: %s", migration.version, migration.description)
        try:
            sync_db = Database.sync_db
            if sync_db is None:
                Database.connect_sync()
                sync_db = Database.sync_db

            # Migrations use sync PyMongo for simplicity (DML operations)
            success = migration.up(sync_db)
            if success:
                sync_db[MIGRATIONS_COLLECTION].insert_one({
                    "version": migration.version,
                    "description": migration.description,
                    "applied_at": datetime.now(timezone.utc),
                })
                count += 1
                logger.info("Migration %s applied successfully", migration.version)
            else:
                logger.error("Migration %s failed", migration.version)
                return count
        except Exception as e:
            logger.error("Migration %s failed with error: %s", migration.version, e)
            return count

    return count


def get_migration_status() -> List[dict]:
    """Return applied migration records for inspection."""
    col = get_collection(MIGRATIONS_COLLECTION)
    if col is None:
        return []
    docs = col.find().sort("applied_at", 1)
    return [
        {
            "version": d["version"],
            "description": d["description"],
            "applied_at": d["applied_at"].isoformat(),
        }
        for d in docs
    ]
