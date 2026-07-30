"""
Phishing persistence repository.

Centralizes Email Phishing reads/writes across MongoDB and the local degraded
store. Routes and services should use this boundary instead of talking to
Mongo/local JSON directly.
"""

from dataclasses import dataclass
from typing import Any, Dict, List, Optional

try:
    from database.connection import get_collection
    from services.phishing_local_store import get_phishing_local_store
except ImportError:
    try:
        from backend.database.connection import get_collection
        from backend.services.phishing_local_store import get_phishing_local_store
    except ImportError:
        get_collection = None
        get_phishing_local_store = None


@dataclass
class RepositoryResult:
    records: List[Dict[str, Any]]
    data_source: str


class PhishingRepository:
    def __init__(self) -> None:
        self._collections = {}

    def save_scan(self, scan_doc: Dict[str, Any]) -> bool:
        self._append_local("scan", scan_doc)
        return self._insert_database("email_scans", scan_doc)

    def save_threat(self, threat_doc: Dict[str, Any]) -> bool:
        self._append_local("threat", threat_doc)
        return self._insert_database("threats", threat_doc)

    def save_activity_log(self, log_doc: Dict[str, Any]) -> bool:
        self._append_local("log", log_doc)
        return self._insert_database("activity_logs", log_doc)

    def update_scan(self, scan_id: Optional[str], updates: Dict[str, Any]) -> bool:
        if not scan_id or not updates:
            return False
        self._update_local("scan", scan_id, updates)
        return self._update_database("email_scans", "scan_id", scan_id, updates)

    def update_threat(self, threat_id: Optional[str], updates: Dict[str, Any]) -> bool:
        if not threat_id or not updates:
            return False
        self._update_local("threat", threat_id, updates)
        return self._update_database("threats", "threat_id", threat_id, updates)

    def list_scans(
        self,
        limit: int = 100,
        is_phishing: Optional[bool] = None,
    ) -> RepositoryResult:
        records = []
        sources = set()

        local_records = self._list_local_scans(limit=limit, is_phishing=is_phishing)
        if local_records:
            records.extend(local_records)
            sources.add("local")

        collection = self._collection("email_scans")
        if collection is not None:
            query = {}
            if is_phishing is not None:
                query["is_phishing"] = is_phishing
            try:
                database_records = list(
                    collection.find(query).sort("scanned_at", -1).limit(limit)
                )
                if database_records:
                    records.extend(database_records)
                    sources.add("database")
            except Exception as exc:
                print(f"PhishingRepository email scan read failed: {exc}")

        return RepositoryResult(
            records=self._dedupe_latest(records, "scan_id", "scanned_at", limit),
            data_source=self._source_label(sources),
        )

    def list_threats(
        self,
        limit: int = 100,
        severity: Optional[str] = None,
        status: Optional[str] = None,
    ) -> RepositoryResult:
        records = []
        sources = set()

        local_records = self._list_local_threats(limit=limit)
        if local_records:
            records.extend(local_records)
            sources.add("local")

        collection = self._collection("threats")
        if collection is not None:
            query = {}
            if severity:
                query["severity"] = severity.upper()
            if status:
                query["status"] = status.lower()
            try:
                database_records = list(
                    collection.find(query).sort("detected_at", -1).limit(limit)
                )
                if database_records:
                    records.extend(database_records)
                    sources.add("database")
            except Exception as exc:
                print(f"PhishingRepository threat read failed: {exc}")

        filtered_records = [
            record
            for record in records
            if self._matches_threat_filters(record, severity=severity, status=status)
        ]
        return RepositoryResult(
            records=self._dedupe_latest(filtered_records, "threat_id", "detected_at", limit),
            data_source=self._source_label(sources),
        )

    def list_activity_logs(
        self,
        limit: int = 100,
        event_type: Optional[str] = None,
    ) -> RepositoryResult:
        records = []
        sources = set()

        local_records = self._list_local_logs(limit=limit, event_type=event_type)
        if local_records:
            records.extend(local_records)
            sources.add("local")

        collection = self._collection("activity_logs")
        if collection is not None:
            query = {}
            if event_type:
                query["event"] = event_type
            try:
                database_records = list(
                    collection.find(query).sort("timestamp", -1).limit(limit)
                )
                if database_records:
                    records.extend(database_records)
                    sources.add("database")
            except Exception as exc:
                print(f"PhishingRepository activity log read failed: {exc}")

        return RepositoryResult(
            records=self._dedupe_latest(records, "id", "timestamp", limit),
            data_source=self._source_label(sources),
        )

    def get_threat(self, threat_id: str) -> Optional[Dict[str, Any]]:
        if get_phishing_local_store is not None:
            try:
                threat = get_phishing_local_store().get_threat(threat_id)
                if threat:
                    return threat
            except Exception as exc:
                print(f"PhishingRepository local threat detail failed: {exc}")

        collection = self._collection("threats")
        if collection is None:
            return None
        try:
            return collection.find_one({"threat_id": threat_id})
        except Exception as exc:
            print(f"PhishingRepository database threat detail failed: {exc}")
            return None

    def get_scan(self, scan_id: str) -> Optional[Dict[str, Any]]:
        for scan in self._list_local_scans(limit=500, is_phishing=None):
            if scan.get("scan_id") == scan_id:
                return scan

        collection = self._collection("email_scans")
        if collection is None:
            return None
        try:
            return collection.find_one({"scan_id": scan_id})
        except Exception as exc:
            print(f"PhishingRepository database scan detail failed: {exc}")
            return None

    def _collection(self, name: str):
        if get_collection is None:
            return None
        if name in self._collections:
            return self._collections[name]
        try:
            collection = get_collection(name)
            if collection is not None:
                self._collections[name] = collection
            return collection
        except Exception as exc:
            print(f"PhishingRepository collection unavailable ({name}): {exc}")
            return None

    def _insert_database(self, collection_name: str, document: Dict[str, Any]) -> bool:
        collection = self._collection(collection_name)
        if collection is None:
            return False
        try:
            collection.insert_one(document.copy())
            return True
        except Exception as exc:
            print(f"PhishingRepository {collection_name} insert failed: {exc}")
            return False

    def _update_database(
        self,
        collection_name: str,
        key: str,
        value: str,
        updates: Dict[str, Any],
    ) -> bool:
        collection = self._collection(collection_name)
        if collection is None:
            return False
        try:
            collection.update_one({key: value}, {"$set": updates})
            return True
        except Exception as exc:
            print(f"PhishingRepository {collection_name} update failed: {exc}")
            return False

    def _append_local(self, record_type: str, document: Dict[str, Any]) -> None:
        if get_phishing_local_store is None:
            return
        try:
            store = get_phishing_local_store()
            if record_type == "scan":
                store.append_scan(document)
            elif record_type == "threat":
                store.append_threat(document)
            elif record_type == "log":
                store.append_log(document)
        except Exception as exc:
            print(f"PhishingRepository local {record_type} append failed: {exc}")

    def _update_local(self, record_type: str, record_id: str, updates: Dict[str, Any]) -> None:
        if get_phishing_local_store is None:
            return
        try:
            store = get_phishing_local_store()
            if record_type == "scan":
                store.update_scan(record_id, updates)
            elif record_type == "threat":
                store.update_threat(record_id, updates)
        except Exception as exc:
            print(f"PhishingRepository local {record_type} update failed: {exc}")

    def _list_local_scans(self, limit: int, is_phishing: Optional[bool]) -> List[Dict[str, Any]]:
        if get_phishing_local_store is None:
            return []
        try:
            return get_phishing_local_store().list_scans(limit=limit, is_phishing=is_phishing)
        except Exception as exc:
            print(f"PhishingRepository local scan read failed: {exc}")
            return []

    def _list_local_threats(self, limit: int) -> List[Dict[str, Any]]:
        if get_phishing_local_store is None:
            return []
        try:
            return get_phishing_local_store().list_threats(limit=limit)
        except Exception as exc:
            print(f"PhishingRepository local threat read failed: {exc}")
            return []

    def _list_local_logs(self, limit: int, event_type: Optional[str]) -> List[Dict[str, Any]]:
        if get_phishing_local_store is None:
            return []
        try:
            return get_phishing_local_store().list_logs(limit=limit, event_type=event_type)
        except Exception as exc:
            print(f"PhishingRepository local log read failed: {exc}")
            return []

    def _matches_threat_filters(
        self,
        record: Dict[str, Any],
        severity: Optional[str],
        status: Optional[str],
    ) -> bool:
        if severity and str(record.get("severity", "")).upper() != severity.upper():
            return False
        if status and str(record.get("status", "")).lower() != status.lower():
            return False
        return True

    def _dedupe_latest(
        self,
        records: List[Dict[str, Any]],
        primary_key: str,
        timestamp_key: str,
        limit: int,
    ) -> List[Dict[str, Any]]:
        deduped = {}
        for index, record in enumerate(records):
            record_key = record.get(primary_key) or record.get("_id") or f"{primary_key}-{index}"
            deduped[str(record_key)] = record
        return sorted(
            deduped.values(),
            key=lambda item: str(item.get(timestamp_key, "")),
            reverse=True,
        )[:limit]

    def _source_label(self, sources: set) -> str:
        return "+".join(sorted(sources)) if sources else "empty"


_repository: Optional[PhishingRepository] = None


def get_phishing_repository() -> PhishingRepository:
    global _repository
    if _repository is None:
        _repository = PhishingRepository()
    return _repository
