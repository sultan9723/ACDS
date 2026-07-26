"""
Migration v004: Reports Schema
==============================
Adds a proper schema and indexes for the `reports` collection,
and seeds the first report type metadata document.
"""

from datetime import datetime, timezone

from database.migrations.base import Migration


REPORT_TYPES = [
    {"type": "threat_summary", "name": "Threat Summary",
     "description": "Overview of all detected threats with severity breakdown"},
    {"type": "detection_analysis", "name": "Detection Analysis",
     "description": "Detailed analysis of detection patterns and trends"},
    {"type": "incident_log", "name": "Incident Log",
     "description": "Chronological log of all security incidents"},
    {"type": "performance_metrics", "name": "Performance Metrics",
     "description": "System performance and detection accuracy metrics"},
    {"type": "executive_summary", "name": "Executive Summary",
     "description": "High-level summary for management review"},
    {"type": "compliance_report", "name": "Compliance Report",
     "description": "Compliance-focused security posture report"},
]


class ReportsSchema(Migration):
    version = "004"
    description = "Set up reports collection with schema validation and metadata"

    def up(self, db) -> bool:
        existing = db.list_collection_names()
        if "reports" not in existing:
            db.create_collection("reports")

        # Ensure indexes
        existing_indexes = [idx["name"] for idx in db.reports.list_indexes()]
        if "report_id_1" not in existing_indexes:
            db.reports.create_index("report_id", unique=True)
        if "generated_at_-1" not in existing_indexes:
            db.reports.create_index([("generated_at", -1)])
        if "report_type_1" not in existing_indexes:
            db.reports.create_index("report_type")
        if "generated_by_1" not in existing_indexes:
            db.reports.create_index("generated_by")

        # Insert report-type metadata documents so the collection is not empty
        existing_meta = db.reports.find_one({"type": "metadata"})
        if not existing_meta:
            db.reports.insert_one({
                "type": "metadata",
                "report_types": REPORT_TYPES,
                "created_at": datetime.now(timezone.utc),
            })

        return True

    def down(self, db) -> bool:
        try:
            db.reports.delete_many({"type": "metadata"})
            db.reports.drop_index("report_id_1")
            db.reports.drop_index("generated_at_-1")
            db.reports.drop_index("report_type_1")
            db.reports.drop_index("generated_by_1")
        except Exception:
            pass
        return True
