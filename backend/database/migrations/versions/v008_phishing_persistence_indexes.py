"""
Migration v008: Phishing Persistence Indexes
============================================
Adds query indexes for persisted phishing scans, threats, and activity logs.
"""

from database.migrations.base import Migration


class PhishingPersistenceIndexes(Migration):
    version = "008"
    description = "Add phishing persistence indexes"

    def up(self, db) -> bool:
        db.email_scans.create_index("scan_id", unique=True, name="email_scan_id_unique")
        db.email_scans.create_index([("scanned_at", -1)], name="email_scanned_at_desc")
        db.email_scans.create_index(
            [("session_id", 1), ("scanned_at", -1)],
            name="email_session_scanned_at",
        )
        db.email_scans.create_index(
            [("is_phishing", 1), ("scanned_at", -1)],
            name="email_is_phishing_scanned_at",
        )
        db.email_scans.create_index(
            [("data_source", 1), ("scanned_at", -1)],
            name="email_data_source_scanned_at",
        )

        db.threats.create_index("threat_id", unique=True, name="threat_id_unique")
        db.threats.create_index(
            [("module", 1), ("detected_at", -1)],
            name="threat_module_detected_at",
        )
        db.threats.create_index(
            [("severity", 1), ("detected_at", -1)],
            name="threat_severity_detected_at",
        )
        db.threats.create_index(
            [("status", 1), ("updated_at", -1)],
            name="threat_status_updated_at",
        )
        db.threats.create_index(
            [("session_id", 1), ("detected_at", -1)],
            name="threat_session_detected_at",
        )

        db.activity_logs.create_index(
            [("timestamp", -1)],
            name="activity_timestamp_desc",
        )
        db.activity_logs.create_index(
            [("module", 1), ("timestamp", -1)],
            name="activity_module_timestamp",
        )
        db.activity_logs.create_index(
            [("event", 1), ("timestamp", -1)],
            name="activity_event_timestamp",
        )
        db.activity_logs.create_index(
            [("session_id", 1), ("timestamp", -1)],
            name="activity_session_timestamp",
        )
        db.activity_logs.create_index("id", name="activity_id_lookup")
        db.activity_logs.create_index("scan_id", name="activity_scan_id")
        db.activity_logs.create_index("threat_id", name="activity_threat_id")
        return True

    def down(self, db) -> bool:
        indexes_by_collection = {
            "email_scans": [
                "email_scan_id_unique",
                "email_scanned_at_desc",
                "email_session_scanned_at",
                "email_is_phishing_scanned_at",
                "email_data_source_scanned_at",
            ],
            "threats": [
                "threat_id_unique",
                "threat_module_detected_at",
                "threat_severity_detected_at",
                "threat_status_updated_at",
                "threat_session_detected_at",
            ],
            "activity_logs": [
                "activity_timestamp_desc",
                "activity_module_timestamp",
                "activity_event_timestamp",
                "activity_session_timestamp",
                "activity_id_lookup",
                "activity_scan_id",
                "activity_threat_id",
            ],
        }

        existing_collections = db.list_collection_names()
        for collection_name, index_names in indexes_by_collection.items():
            if collection_name not in existing_collections:
                continue
            for index_name in index_names:
                try:
                    db[collection_name].drop_index(index_name)
                except Exception:
                    pass
        return True
