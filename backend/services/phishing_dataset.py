"""
Phishing test dataset loader.

Loads local CSV/JSON/JSONL phishing datasets for module test runs, validates
records, normalizes labels, and falls back to curated built-in samples when no
configured dataset file is available.
"""

import csv
import hashlib
import json
import os
import random
from copy import deepcopy
from dataclasses import dataclass
from email import policy
from email.parser import Parser
from email.utils import parseaddr
from pathlib import Path
from typing import Any, Dict, List, Optional, Tuple


DATASET_SOURCE = "phishing_test_dataset"
FALLBACK_DATASET_SOURCE = "curated_builtin_fallback"
BACKEND_DIR = Path(__file__).resolve().parents[1]
PROJECT_ROOT = BACKEND_DIR.parent

DEFAULT_DATASET_PATHS = [
    BACKEND_DIR / "data" / "phishing_dataset.csv",
    BACKEND_DIR / "data" / "phishing_dataset.jsonl",
    BACKEND_DIR / "data" / "phishing_dataset.json",
    PROJECT_ROOT / "data" / "phishing_dataset.csv",
    PROJECT_ROOT / "data" / "phishing_dataset.jsonl",
    PROJECT_ROOT / "data" / "phishing_dataset.json",
]

SUBJECT_KEYS = ("subject", "email_subject", "title")
SENDER_KEYS = ("sender", "from", "email_sender", "source")
RECIPIENT_KEYS = ("recipient", "to", "email_recipient")
CONTENT_KEYS = (
    "content",
    "body",
    "text",
    "email",
    "email_text",
    "email content",
    "email_content",
    "message",
    "raw",
    "raw_email",
    "email text",
)
LABEL_KEYS = (
    "expected_label",
    "label",
    "class",
    "category",
    "type",
    "target",
    "is_phishing",
    "phishing",
)

FALLBACK_DATASET = {
    "phishing": [
        {
            "subject": "URGENT: Verify your account today",
            "sender": "security-alert@bankofamerica-verify.com",
            "content": (
                "Dear customer, suspicious activity was detected on your account. "
                "Verify your identity immediately at http://secure-bankofamerica-login.com/verify "
                "or your account will be suspended within 24 hours."
            ),
        },
        {
            "subject": "Microsoft 365 password expiration notice",
            "sender": "admin@microsoft365-support.net",
            "content": (
                "Your Microsoft 365 password will expire in 2 hours. Update your password now "
                "at http://microsoft365-update.com/password to avoid service interruption."
            ),
        },
        {
            "subject": "PayPal account limited",
            "sender": "service@paypa1-secure.com",
            "content": (
                "We noticed unusual login activity on your PayPal account. Confirm your information "
                "at http://paypal-verify.xyz/confirm within 48 hours to restore access."
            ),
        },
        {
            "subject": "Invoice payment required immediately",
            "sender": "billing@quickbooks-invoices.com",
            "content": (
                "Invoice INV-2026-8847 is overdue. Pay now at "
                "http://quickbooks-pay-secure.com/invoice/INV-2026-8847 to avoid collections."
            ),
        },
        {
            "subject": "Apple ID locked after unusual sign-in",
            "sender": "appleid@apple-support-verify.com",
            "content": (
                "Your Apple ID was locked after a sign-in attempt from an unknown device. "
                "Verify now at http://appleid-verify-support.com/unlock or access may be disabled."
            ),
        },
    ],
    "legitimate": [
        {
            "subject": "Weekly project update",
            "sender": "manager@company.com",
            "content": (
                "Hi team, here is the weekly project update. We completed the API review, "
                "updated the timeline, and will meet tomorrow to discuss next steps."
            ),
        },
        {
            "subject": "Meeting notes from today's call",
            "sender": "colleague@company.com",
            "content": (
                "Thanks for joining today. Action items are attached in the shared workspace. "
                "Please add comments before Friday's planning session."
            ),
        },
        {
            "subject": "Your Amazon.com order has shipped",
            "sender": "ship-confirm@amazon.com",
            "content": (
                "Your order has shipped. You can track it from your Amazon account order history. "
                "Estimated delivery is listed in your account."
            ),
        },
    ],
}


@dataclass
class DatasetSelection:
    samples: List[Dict[str, Any]]
    metadata: Dict[str, Any]


class PhishingDatasetLoader:
    def __init__(self, dataset_path: Optional[str] = None) -> None:
        self.dataset_path = dataset_path or os.getenv("PHISHING_TEST_DATASET_PATH")
        self._cached_records: Optional[List[Dict[str, Any]]] = None
        self._cached_metadata: Optional[Dict[str, Any]] = None

    def get_dataset_metadata(self) -> Dict[str, Any]:
        self._load_records()
        return deepcopy(self._cached_metadata or {})

    def select_samples(
        self,
        count: int,
        include_legitimate: bool = True,
        seed: Optional[int] = None,
    ) -> DatasetSelection:
        records = self._load_records()
        rng = random.Random(seed) if seed is not None else random.Random()

        phishing = [record for record in records if record["expected_label"] == "phishing"]
        legitimate = [record for record in records if record["expected_label"] == "legitimate"]

        if include_legitimate:
            phishing_count, legitimate_count = self._balanced_counts(count, len(phishing), len(legitimate))
        else:
            phishing_count, legitimate_count = count, 0

        samples = []
        samples.extend(self._sample_pool(phishing, phishing_count, rng))
        samples.extend(self._sample_pool(legitimate, legitimate_count, rng))
        rng.shuffle(samples)

        duplicate_count = len(samples) - len({sample["dataset_record_id"] for sample in samples})
        metadata = deepcopy(self._cached_metadata or {})
        metadata.update(
            {
                "requested_count": count,
                "selected_count": len(samples),
                "selected_phishing": sum(1 for sample in samples if sample["expected_label"] == "phishing"),
                "selected_legitimate": sum(1 for sample in samples if sample["expected_label"] == "legitimate"),
                "include_legitimate": include_legitimate,
                "seed": seed,
                "duplicates_used": duplicate_count,
                "sampling_strategy": "balanced_without_replacement_then_fill",
            }
        )
        return DatasetSelection(samples=samples, metadata=metadata)

    def _load_records(self) -> List[Dict[str, Any]]:
        if self._cached_records is not None:
            return deepcopy(self._cached_records)

        dataset_path = self._resolve_dataset_path()
        if dataset_path:
            records, metadata = self._load_dataset_file(dataset_path)
            if records:
                self._cached_records = records
                self._cached_metadata = metadata
                return deepcopy(records)

        records = self._fallback_records()
        self._cached_records = records
        self._cached_metadata = self._build_metadata(
            source=FALLBACK_DATASET_SOURCE,
            path=None,
            records=records,
            rejected_records=0,
            warnings=["No configured local phishing dataset found; using curated fallback samples."],
        )
        return deepcopy(records)

    def _resolve_dataset_path(self) -> Optional[Path]:
        candidate_paths = []
        if self.dataset_path:
            candidate_paths.append(Path(self.dataset_path))
        candidate_paths.extend(DEFAULT_DATASET_PATHS)

        for path in candidate_paths:
            resolved = path if path.is_absolute() else PROJECT_ROOT / path
            if resolved.exists() and resolved.is_file():
                return resolved
        return None

    def _load_dataset_file(self, path: Path) -> Tuple[List[Dict[str, Any]], Dict[str, Any]]:
        warnings = []
        raw_rows = self._read_rows(path)
        records = []
        seen_ids = set()
        rejected = 0

        for index, row in enumerate(raw_rows, start=1):
            record = self._normalize_row(row, source_path=path, row_number=index)
            if not record:
                rejected += 1
                continue
            record_id = record["dataset_record_id"]
            if record_id in seen_ids:
                continue
            seen_ids.add(record_id)
            records.append(record)

        if not any(record["expected_label"] == "phishing" for record in records):
            warnings.append("Dataset has no phishing-labeled records.")
        if not any(record["expected_label"] == "legitimate" for record in records):
            warnings.append("Dataset has no legitimate-labeled records.")

        return records, self._build_metadata(
            source=DATASET_SOURCE,
            path=path,
            records=records,
            rejected_records=rejected,
            warnings=warnings,
        )

    def _read_rows(self, path: Path) -> List[Dict[str, Any]]:
        suffix = path.suffix.lower()
        if suffix == ".csv":
            with path.open("r", encoding="utf-8-sig", newline="") as handle:
                return [dict(row) for row in csv.DictReader(handle)]
        if suffix == ".jsonl":
            rows = []
            with path.open("r", encoding="utf-8") as handle:
                for line in handle:
                    line = line.strip()
                    if line:
                        rows.append(json.loads(line))
            return rows
        if suffix == ".json":
            with path.open("r", encoding="utf-8") as handle:
                data = json.load(handle)
            if isinstance(data, list):
                return data
            if isinstance(data, dict):
                for key in ("records", "emails", "data", "samples"):
                    if isinstance(data.get(key), list):
                        return data[key]
        return []

    def _normalize_row(
        self,
        row: Dict[str, Any],
        source_path: Optional[Path],
        row_number: int,
    ) -> Optional[Dict[str, Any]]:
        if not isinstance(row, dict):
            return None
        normalized_row = {str(key).strip().lower(): value for key, value in row.items()}
        raw_content = self._first_value(normalized_row, CONTENT_KEYS)
        subject = self._first_value(normalized_row, SUBJECT_KEYS)
        sender = self._first_value(normalized_row, SENDER_KEYS)
        recipient = self._first_value(normalized_row, RECIPIENT_KEYS)
        label = self._normalize_label(self._first_value(normalized_row, LABEL_KEYS))

        if raw_content and ("\nfrom:" in f"\n{raw_content.lower()}" or "\nsubject:" in f"\n{raw_content.lower()}"):
            parsed = self._parse_raw_email(raw_content)
            subject = subject or parsed.get("subject")
            sender = sender or parsed.get("sender")
            recipient = recipient or parsed.get("recipient")
            raw_content = parsed.get("content") or raw_content

        content = str(raw_content or "").strip()
        if not content or not label:
            return None

        subject = str(subject or "No Subject").strip()[:200]
        sender = str(sender or "unknown@example.com").strip()[:200]
        recipient = str(recipient or "").strip()[:200] or None
        source = str(source_path) if source_path else FALLBACK_DATASET_SOURCE
        record_id = self._record_id(source, row_number, label, sender, subject, content)

        return {
            "dataset_record_id": record_id,
            "subject": subject,
            "sender": sender,
            "recipient": recipient,
            "content": content,
            "expected_label": label,
            "source": DATASET_SOURCE if source_path else FALLBACK_DATASET_SOURCE,
            "source_path": str(source_path) if source_path else None,
            "row_number": row_number,
        }

    def _parse_raw_email(self, raw_content: str) -> Dict[str, Optional[str]]:
        try:
            message = Parser(policy=policy.default).parsestr(raw_content)
            _sender_name, sender = parseaddr(message.get("from", ""))
            _recipient_name, recipient = parseaddr(message.get("to", ""))
            body = message.get_body(preferencelist=("plain",))
            content = body.get_content() if body else message.get_payload()
            return {
                "subject": message.get("subject"),
                "sender": sender or None,
                "recipient": recipient or None,
                "content": content if isinstance(content, str) else raw_content,
            }
        except Exception:
            return {"content": raw_content}

    def _fallback_records(self) -> List[Dict[str, Any]]:
        records = []
        row_number = 0
        for label, samples in FALLBACK_DATASET.items():
            for sample in samples:
                row_number += 1
                record = self._normalize_row(sample | {"expected_label": label}, None, row_number)
                if record:
                    records.append(record)
        return records

    def _balanced_counts(self, count: int, phishing_available: int, legitimate_available: int) -> Tuple[int, int]:
        if phishing_available <= 0:
            return 0, count
        if legitimate_available <= 0:
            return count, 0
        phishing_count = (count + 1) // 2
        legitimate_count = count - phishing_count
        return phishing_count, legitimate_count

    def _sample_pool(
        self,
        pool: List[Dict[str, Any]],
        count: int,
        rng: random.Random,
    ) -> List[Dict[str, Any]]:
        if count <= 0 or not pool:
            return []
        shuffled = [deepcopy(record) for record in pool]
        rng.shuffle(shuffled)
        if count <= len(shuffled):
            return shuffled[:count]

        selected = shuffled[:]
        while len(selected) < count:
            selected.append(deepcopy(rng.choice(pool)))
        return selected

    def _build_metadata(
        self,
        source: str,
        path: Optional[Path],
        records: List[Dict[str, Any]],
        rejected_records: int,
        warnings: List[str],
    ) -> Dict[str, Any]:
        phishing_count = sum(1 for record in records if record["expected_label"] == "phishing")
        legitimate_count = sum(1 for record in records if record["expected_label"] == "legitimate")
        return {
            "source": source,
            "path": str(path) if path else None,
            "total_records": len(records),
            "phishing_records": phishing_count,
            "legitimate_records": legitimate_count,
            "rejected_records": rejected_records,
            "warnings": warnings,
            "supported_formats": ["csv", "json", "jsonl"],
        }

    def _first_value(self, row: Dict[str, Any], keys: Tuple[str, ...]) -> Optional[str]:
        for key in keys:
            value = row.get(key)
            if value is not None and str(value).strip():
                return str(value)
        return None

    def _normalize_label(self, value: Optional[str]) -> Optional[str]:
        label = str(value or "").strip().lower()
        if label in {"1", "true", "yes", "phish", "phishing", "malicious", "spam", "positive"}:
            return "phishing"
        if label in {"0", "false", "no", "safe", "ham", "legitimate", "benign", "negative"}:
            return "legitimate"
        return None

    def _record_id(
        self,
        source: str,
        row_number: int,
        label: str,
        sender: str,
        subject: str,
        content: str,
    ) -> str:
        digest = hashlib.sha256(
            f"{source}|{row_number}|{label}|{sender}|{subject}|{content[:500]}".encode("utf-8")
        ).hexdigest()[:16]
        return f"PDS-{digest.upper()}"


_dataset_loader: Optional[PhishingDatasetLoader] = None


def get_phishing_dataset_loader() -> PhishingDatasetLoader:
    global _dataset_loader
    if _dataset_loader is None:
        _dataset_loader = PhishingDatasetLoader()
    return _dataset_loader
