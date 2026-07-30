"""
Migration v010: Phishing Evaluation Indexes
===========================================
Adds indexes for test-run evaluation fields on phishing records and logs.
"""

from database.migrations.base import Migration


class PhishingEvaluationIndexes(Migration):
    version = "010"
    description = "Add phishing evaluation metric indexes"

    def up(self, db) -> bool:
        db.email_scans.create_index(
            [("evaluation_outcome", 1), ("scanned_at", -1)],
            name="email_evaluation_outcome_scanned_at",
        )
        db.email_scans.create_index(
            [("correct", 1), ("scanned_at", -1)],
            name="email_correct_scanned_at",
        )
        db.email_scans.create_index(
            [("expected_label", 1), ("predicted_label", 1), ("scanned_at", -1)],
            name="email_expected_predicted_scanned_at",
        )

        db.threats.create_index(
            [("evaluation_outcome", 1), ("detected_at", -1)],
            name="threat_evaluation_outcome_detected_at",
        )
        db.threats.create_index(
            [("correct", 1), ("detected_at", -1)],
            name="threat_correct_detected_at",
        )
        db.threats.create_index(
            [("expected_label", 1), ("predicted_label", 1), ("detected_at", -1)],
            name="threat_expected_predicted_detected_at",
        )

        db.activity_logs.create_index(
            [("evaluation_outcome", 1), ("timestamp", -1)],
            name="activity_evaluation_outcome_timestamp",
        )
        db.activity_logs.create_index(
            [("correct", 1), ("timestamp", -1)],
            name="activity_correct_timestamp",
        )
        return True

    def down(self, db) -> bool:
        indexes_by_collection = {
            "email_scans": [
                "email_evaluation_outcome_scanned_at",
                "email_correct_scanned_at",
                "email_expected_predicted_scanned_at",
            ],
            "threats": [
                "threat_evaluation_outcome_detected_at",
                "threat_correct_detected_at",
                "threat_expected_predicted_detected_at",
            ],
            "activity_logs": [
                "activity_evaluation_outcome_timestamp",
                "activity_correct_timestamp",
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
