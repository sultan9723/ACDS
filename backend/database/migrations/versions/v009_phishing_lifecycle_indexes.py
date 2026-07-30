"""
Migration v009: Phishing Lifecycle Indexes
==========================================
Adds indexes for lifecycle/report trace fields introduced on phishing records.
"""

from database.migrations.base import Migration


class PhishingLifecycleIndexes(Migration):
    version = "009"
    description = "Add phishing lifecycle trace indexes"

    def up(self, db) -> bool:
        db.email_scans.create_index(
            [("lifecycle_state", 1), ("scanned_at", -1)],
            name="email_lifecycle_scanned_at",
        )
        db.email_scans.create_index(
            [("report_status", 1), ("scanned_at", -1)],
            name="email_report_status_scanned_at",
        )

        db.threats.create_index(
            [("lifecycle_state", 1), ("detected_at", -1)],
            name="threat_lifecycle_detected_at",
        )
        db.threats.create_index(
            [("report_status", 1), ("detected_at", -1)],
            name="threat_report_status_detected_at",
        )
        db.threats.create_index("report_id", name="threat_report_id")

        db.activity_logs.create_index(
            [("lifecycle_state", 1), ("timestamp", -1)],
            name="activity_lifecycle_timestamp",
        )
        db.activity_logs.create_index(
            [("report_status", 1), ("timestamp", -1)],
            name="activity_report_status_timestamp",
        )
        db.activity_logs.create_index("report_id", name="activity_report_id")
        return True

    def down(self, db) -> bool:
        indexes_by_collection = {
            "email_scans": [
                "email_lifecycle_scanned_at",
                "email_report_status_scanned_at",
            ],
            "threats": [
                "threat_lifecycle_detected_at",
                "threat_report_status_detected_at",
                "threat_report_id",
            ],
            "activity_logs": [
                "activity_lifecycle_timestamp",
                "activity_report_status_timestamp",
                "activity_report_id",
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
