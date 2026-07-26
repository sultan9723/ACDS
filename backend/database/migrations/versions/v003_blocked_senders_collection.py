"""
Migration v003: Blocked Senders Collection
==========================================
Migrates blocked_senders from a JSON file into a dedicated MongoDB collection
so it benefits from indexing, querying, and consistency with the rest of the
system.
"""

import json
import os
from datetime import datetime, timezone

from database.migrations.base import Migration


COLLECTION_NAME = "blocked_senders"


class BlockedSendersCollection(Migration):
    version = "003"
    description = "Create blocked_senders collection and migrate from JSON file"

    def up(self, db) -> bool:
        existing = db.list_collection_names()
        if COLLECTION_NAME not in existing:
            db.create_collection(COLLECTION_NAME)

        db.blocked_senders.create_index("email", unique=True)
        db.blocked_senders.create_index([("blocked_at", -1)])
        db.blocked_senders.create_index("blocked_by")

        # If there is already a JSON file, migrate it
        json_paths = [
            "data/blocked_senders.json",
            "backend/data/blocked_senders.json",
        ]
        for path in json_paths:
            if os.path.isfile(path):
                try:
                    with open(path) as f:
                        senders = json.load(f)
                except (json.JSONDecodeError, Exception):
                    continue

                if isinstance(senders, list):
                    for entry in senders:
                        email = entry.get("email")
                        if not email:
                            continue
                        existing_doc = db.blocked_senders.find_one({"email": email})
                        if not existing_doc:
                            doc = {
                                "email": email,
                                "blocked_at": entry.get(
                                    "blocked_at", datetime.now(timezone.utc)
                                ),
                                "reason": entry.get("reason"),
                                "blocked_by": entry.get("blocked_by"),
                            }
                            db.blocked_senders.insert_one(doc)
                break

        return True

    def down(self, db) -> bool:
        try:
            db[COLLECTION_NAME].drop()
        except Exception:
            pass
        return True
