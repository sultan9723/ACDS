"""
Migration v007: Authentication Hardening State Indexes
======================================================
Adds persistent state collections for login throttling and token revocation.
"""

from database.migrations.base import Migration


class AuthHardeningStateIndexes(Migration):
    version = "007"
    description = "Add authentication hardening state indexes"

    def up(self, db) -> bool:
        existing = db.list_collection_names()
        if "auth_rate_limits" not in existing:
            db.create_collection("auth_rate_limits")
        if "revoked_tokens" not in existing:
            db.create_collection("revoked_tokens")

        db.auth_rate_limits.create_index("key", unique=True)
        db.auth_rate_limits.create_index([("updated_at", -1)])
        db.auth_rate_limits.create_index("expires_at", expireAfterSeconds=0)

        db.revoked_tokens.create_index("jti", unique=True)
        db.revoked_tokens.create_index("user_id")
        db.revoked_tokens.create_index("expires_at", expireAfterSeconds=0)
        return True

    def down(self, db) -> bool:
        for collection_name in ("auth_rate_limits", "revoked_tokens"):
            if collection_name in db.list_collection_names():
                db[collection_name].drop()
        return True
