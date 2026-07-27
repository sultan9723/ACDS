"""
Local durable store for phishing test-run artifacts.

This is a fallback audit store for development and degraded database states. It
keeps Email Phishing test-run scans, threats, and activity logs visible after a
page reload when MongoDB writes are unavailable or unauthorized.
"""

import json
import os
import threading
from copy import deepcopy
from datetime import datetime, timezone
from typing import Any, Dict, List, Optional

STORE_PATH = os.path.join(
    os.path.dirname(os.path.dirname(__file__)),
    "data",
    "phishing_test_run_store.json",
)


class PhishingLocalStore:
    def __init__(self, store_path: str = STORE_PATH) -> None:
        self.store_path = store_path
        self._lock = threading.RLock()
        self._ensure_store()

    def append_scan(self, scan: Dict[str, Any]) -> None:
        self._append("scans", scan)

    def append_threat(self, threat: Dict[str, Any]) -> None:
        self._append("threats", threat)

    def append_log(self, log: Dict[str, Any]) -> None:
        self._append("activity_logs", log)

    def update_scan(self, scan_id: Optional[str], updates: Dict[str, Any]) -> None:
        if not scan_id or not updates:
            return
        self._update("scans", "scan_id", scan_id, updates)

    def update_threat(self, threat_id: Optional[str], updates: Dict[str, Any]) -> None:
        if not threat_id or not updates:
            return
        self._update("threats", "threat_id", threat_id, updates)

    def list_scans(self, limit: int = 100, is_phishing: Optional[bool] = None) -> List[Dict[str, Any]]:
        records = self._read().get("scans", [])
        if is_phishing is not None:
            records = [item for item in records if bool(item.get("is_phishing")) is is_phishing]
        return self._latest(records, "scanned_at", limit)

    def list_threats(self, limit: int = 100) -> List[Dict[str, Any]]:
        return self._latest(self._read().get("threats", []), "detected_at", limit)

    def list_logs(self, limit: int = 100, event_type: Optional[str] = None) -> List[Dict[str, Any]]:
        records = self._read().get("activity_logs", [])
        if event_type:
            records = [item for item in records if item.get("event") == event_type]
        return self._latest(records, "timestamp", limit)

    def get_threat(self, threat_id: str) -> Optional[Dict[str, Any]]:
        for threat in self._read().get("threats", []):
            if threat.get("threat_id") == threat_id:
                return threat
        return None

    def _append(self, collection_name: str, record: Dict[str, Any]) -> None:
        with self._lock:
            data = self._read()
            data.setdefault(collection_name, []).append(self._json_ready(record))
            self._trim(data)
            self._write(data)

    def _update(self, collection_name: str, key: str, value: str, updates: Dict[str, Any]) -> None:
        with self._lock:
            data = self._read()
            for item in data.get(collection_name, []):
                if item.get(key) == value:
                    item.update(self._json_ready(updates))
                    break
            self._write(data)

    def _ensure_store(self) -> None:
        os.makedirs(os.path.dirname(self.store_path), exist_ok=True)
        if not os.path.exists(self.store_path):
            self._write({"scans": [], "threats": [], "activity_logs": []})

    def _read(self) -> Dict[str, List[Dict[str, Any]]]:
        try:
            with open(self.store_path, "r", encoding="utf-8") as handle:
                data = json.load(handle)
            return {
                "scans": data.get("scans", []),
                "threats": data.get("threats", []),
                "activity_logs": data.get("activity_logs", []),
            }
        except Exception:
            return {"scans": [], "threats": [], "activity_logs": []}

    def _write(self, data: Dict[str, List[Dict[str, Any]]]) -> None:
        with open(self.store_path, "w", encoding="utf-8") as handle:
            json.dump(data, handle, indent=2)

    def _trim(self, data: Dict[str, List[Dict[str, Any]]]) -> None:
        data["scans"] = self._latest(data.get("scans", []), "scanned_at", 500)
        data["threats"] = self._latest(data.get("threats", []), "detected_at", 500)
        data["activity_logs"] = self._latest(data.get("activity_logs", []), "timestamp", 1000)

    def _latest(self, records: List[Dict[str, Any]], timestamp_key: str, limit: int) -> List[Dict[str, Any]]:
        sorted_records = sorted(
            records,
            key=lambda item: self._timestamp_value(item.get(timestamp_key)),
            reverse=True,
        )
        return [deepcopy(item) for item in sorted_records[:limit]]

    def _timestamp_value(self, value: Any) -> float:
        if isinstance(value, datetime):
            return value.timestamp()
        if isinstance(value, str):
            try:
                return datetime.fromisoformat(value.replace("Z", "+00:00")).timestamp()
            except ValueError:
                return 0.0
        return 0.0

    def _json_ready(self, value: Any) -> Any:
        if isinstance(value, datetime):
            return value.isoformat()
        if isinstance(value, dict):
            return {key: self._json_ready(item) for key, item in value.items()}
        if isinstance(value, list):
            return [self._json_ready(item) for item in value]
        return value


_local_store: Optional[PhishingLocalStore] = None


def get_phishing_local_store() -> PhishingLocalStore:
    global _local_store
    if _local_store is None:
        _local_store = PhishingLocalStore()
    return _local_store
