"""
Migration v002: Add TTL Index on Threats
=========================================
Adds a TTL index so resolved / false-positive threats older than 90 days
are automatically purged.
"""

from database.migrations.base import Migration


class AddThreatTtlIndex(Migration):
    version = "002"
    description = "Add TTL index on threats for auto-cleanup of resolved threats"

    def up(self, db) -> bool:
        existing_indexes = [idx["name"] for idx in db.threats.list_indexes()]
        if "resolved_ttl" not in existing_indexes:
            db.threats.create_index(
                [("updated_at", -1)],
                name="resolved_ttl",
                partialFilterExpression={
                    "status": {"$in": ["resolved", "false_positive"]},
                },
            )
        return True

    def down(self, db) -> bool:
        try:
            db.threats.drop_index("resolved_ttl")
        except Exception:
            pass
        return True
