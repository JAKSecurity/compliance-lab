import hashlib
import json
from datetime import UTC, datetime
from pathlib import Path


class AuditLogger:
    """Write JSONL audit entries and maintain a hash chain during one process run."""

    GENESIS_HASH = "0" * 64

    def __init__(self, log_path: Path):
        self._log_path = log_path
        self._previous_hash = self.GENESIS_HASH
        self._entries: list[dict] = []

    def log(
        self,
        agent_id: str,
        action: str,
        resource: str,
        detail: str,
        signature: bytes,
    ) -> dict:
        entry = {
            "timestamp": datetime.now(UTC).isoformat(),
            "agent_id": agent_id,
            "action": action,
            "resource": resource,
            "detail": detail,
            "previous_hash": self._previous_hash,
        }
        entry_hash = self._compute_hash(entry)
        entry["entry_hash"] = entry_hash
        entry["signature"] = signature.hex()

        self._previous_hash = entry_hash
        self._entries.append(entry)

        with open(self._log_path, "a") as f:
            f.write(json.dumps(entry) + "\n")

        return entry

    def verify_chain(self) -> bool:
        """Verify hash chain integrity. Does NOT verify signatures."""
        previous_hash = self.GENESIS_HASH
        for entry in self._entries:
            if entry["previous_hash"] != previous_hash:
                return False
            hashable = {
                k: v for k, v in entry.items() if k not in ("entry_hash", "signature")
            }
            computed = self._compute_hash(hashable)
            if computed != entry["entry_hash"]:
                return False
            previous_hash = entry["entry_hash"]
        return True

    def entry_count(self) -> int:
        return len(self._entries)

    @property
    def entries(self) -> list[dict]:
        return list(self._entries)

    @staticmethod
    def _compute_hash(data: dict) -> str:
        return hashlib.sha256(json.dumps(data, sort_keys=True).encode()).hexdigest()
