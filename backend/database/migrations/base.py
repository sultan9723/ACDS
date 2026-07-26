"""
Migration Base Class
=====================
Abstract base for all database migrations.
"""

from abc import ABC, abstractmethod
from datetime import datetime, timezone
from typing import Optional


class Migration(ABC):
    """Base class for a single database migration."""

    version: str = ""
    description: str = ""
    created_at: datetime = datetime.now(timezone.utc)

    @abstractmethod
    def up(self, db) -> bool:
        """Apply the migration. Returns True on success."""
        ...

    def down(self, db) -> bool:
        """Rollback the migration (optional). Returns True on success."""
        return True
