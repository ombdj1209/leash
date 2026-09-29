"""Append-only, hash-chained audit log. Each entry commits to the previous one, so editing or
deleting any past entry breaks verification from that point on."""
from __future__ import annotations

import hashlib
import json
from pathlib import Path

GENESIS = "0" * 64


class AuditLog:
    def __init__(self, path: str | Path | None = None):
        self.path = Path(path) if path else None
        self.entries: list[dict] = []
        self.head = GENESIS
        if self.path and self.path.exists():
            for line in self.path.read_text().splitlines():
                e = json.loads(line)
                self.entries.append(e)
                self.head = e["hash"]

    @staticmethod
    def _digest(prev: str, body: dict) -> str:
        return hashlib.sha256((prev + json.dumps(body, sort_keys=True, separators=(",", ":"))).encode()).hexdigest()

    def append(self, body: dict) -> str:
        h = self._digest(self.head, body)
        entry = {**body, "prev": self.head, "hash": h, "seq": len(self.entries)}
        self.entries.append(entry)
        self.head = h
        if self.path:
            with self.path.open("a") as f:
                f.write(json.dumps(entry, sort_keys=True) + "\n")
        return h

    def verify(self) -> tuple[bool, int | None]:
        """Returns (ok, index of first bad entry)."""
        prev = GENESIS
        for i, e in enumerate(self.entries):
            body = {k: v for k, v in e.items() if k not in ("prev", "hash", "seq")}
            if e["prev"] != prev or self._digest(prev, body) != e["hash"] or e["seq"] != i:
                return False, i
            prev = e["hash"]
        return True, None
