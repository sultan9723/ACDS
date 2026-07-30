"""
Migration v011: Phishing Review Workflow Indexes
================================================
Adds indexes for analyst review state on phishing scans, threats, and logs.
"""

from database.migrations.base import Migration


class PhishingReviewIndexes(Migration):
    version = "011"
    description = "Add phishing analyst review workflow indexes"

    def up(self, db) -> bool:
        db.email_scans.create_index(
            [("review_status", 1), ("scanned_at", -1)],
            name="email_review_status_scanned_at",
        )
        db.email_scans.create_index(
            [("analyst_verdict", 1), ("reviewed_at", -1)],
            name="email_analyst_verdict_reviewed_at",
        )
        db.email_scans.create_index("review_id", name="email_review_id")

        db.threats.create_index(
            [("review_status", 1), ("detected_at", -1)],
            name="threat_review_status_detected_at",
        )
        db.threats.create_index(
            [("analyst_verdict", 1), ("reviewed_at", -1)],
            name="threat_analyst_verdict_reviewed_at",
        )
        db.threats.create_index("review_id", name="threat_review_id")

        db.activity_logs.create_index(
            [("review_status", 1), ("timestamp", -1)],
            name="activity_review_status_timestamp",
        )
        db.activity_logs.create_index(
            [("analyst_verdict", 1), ("timestamp", -1)],
            name="activity_analyst_verdict_timestamp",
        )
        db.activity_logs.create_index("review_id", name="activity_review_id")
        return True

    def down(self, db) -> bool:
        indexes_by_collection = {
            "email_scans": [
                "email_review_status_scanned_at",
                "email_analyst_verdict_reviewed_at",
                "email_review_id",
            ],
            "threats": [
                "threat_review_status_detected_at",
                "threat_analyst_verdict_reviewed_at",
                "threat_review_id",
            ],
            "activity_logs": [
                "activity_review_status_timestamp",
                "activity_analyst_verdict_timestamp",
                "activity_review_id",
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
