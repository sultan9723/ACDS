"""
Migration v001: Initial Schema
==============================
Creates all core collections and indexes.

Mirrors the functionality of data/mongo-init/init-mongo.js but runs
programmatically so it can be tracked by the migration manager.
"""

from database.migrations.base import Migration


COLLECTIONS = [
    "users",
    "threats",
    "email_scans",
    "feedback",
    "alerts",
    "audit_logs",
    "reports",
    "system_stats",
]


class InitialSchema(Migration):
    version = "001"
    description = "Create core collections and indexes"

    def up(self, db) -> bool:
        # Create collections if they do not exist
        existing = db.list_collection_names()
        for col_name in COLLECTIONS:
            if col_name not in existing:
                db.create_collection(col_name)

        # -- users indexes --
        db.users.create_index("email", unique=True)
        db.users.create_index("role")
        db.users.create_index("is_active")

        # -- threats indexes --
        db.threats.create_index("threat_id", unique=True)
        db.threats.create_index("severity")
        db.threats.create_index("status")
        db.threats.create_index([("detected_at", -1)])
        db.threats.create_index("threat_type")
        db.threats.create_index("email_sender")

        # -- email_scans indexes --
        db.email_scans.create_index("scan_id", unique=True)
        db.email_scans.create_index("is_phishing")
        db.email_scans.create_index([("scanned_at", -1)])
        db.email_scans.create_index("email_sender")

        # -- feedback indexes --
        db.feedback.create_index("feedback_id", unique=True)
        db.feedback.create_index("is_reviewed")
        db.feedback.create_index("feedback_type")
        db.feedback.create_index([("submitted_at", -1)])

        # -- alerts indexes --
        db.alerts.create_index("alert_id", unique=True)
        db.alerts.create_index("is_acknowledged")
        db.alerts.create_index("severity")
        db.alerts.create_index([("created_at", -1)])

        # -- audit_logs indexes --
        db.audit_logs.create_index([("timestamp", -1)])
        db.audit_logs.create_index("user_id")
        db.audit_logs.create_index("action_type")
        db.audit_logs.create_index([("timestamp", -1), ("action_type", 1)])

        # -- reports indexes --
        db.reports.create_index("report_id", unique=True)
        db.reports.create_index([("generated_at", -1)])

        # -- system_stats indexes --
        db.system_stats.create_index([("recorded_at", -1)])
        db.system_stats.create_index("period")
        db.system_stats.create_index([("period", 1), ("recorded_at", -1)])

        return True

    def down(self, db) -> bool:
        for col_name in reversed(COLLECTIONS):
            db[col_name].drop()
        return True
