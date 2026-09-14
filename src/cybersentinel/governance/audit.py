"""
Registro de auditoría inmutable (append-only con encadenamiento de hashes).

Cada entrada incluye el hash de la anterior, formando una cadena verificable
(estilo blockchain ligero). Si alguien altera una entrada pasada, la
verificación de integridad falla. Esto da trazabilidad total de cada decisión
del agente — requisito central de un proyecto sobre IA responsable.
"""
from __future__ import annotations

import hashlib
import json
from dataclasses import dataclass, asdict
from datetime import datetime, timezone
from pathlib import Path
from typing import Any


@dataclass
class AuditEntry:
    index: int
    timestamp: str
    actor: str            # "agent" | "human:<nombre>"
    action: str           # qué se registró
    detail: dict[str, Any]
    prev_hash: str
    entry_hash: str = ""

    def compute_hash(self) -> str:
        payload = {
            "index": self.index,
            "timestamp": self.timestamp,
            "actor": self.actor,
            "action": self.action,
            "detail": self.detail,
            "prev_hash": self.prev_hash,
        }
        blob = json.dumps(payload, sort_keys=True, ensure_ascii=False)
        return hashlib.sha256(blob.encode()).hexdigest()


class AuditLog:
    """Cadena de auditoría persistente en JSON Lines."""

    GENESIS = "0" * 64

    def __init__(self, path: str | Path = "audit_log.jsonl") -> None:
        self.path = Path(path)
        self.entries: list[AuditEntry] = []
        if self.path.exists():
            self._load()

    def _load(self) -> None:
        with open(self.path, "r", encoding="utf-8") as fh:
            for line in fh:
                line = line.strip()
                if line:
                    d = json.loads(line)
                    self.entries.append(AuditEntry(**d))

    def record(self, actor: str, action: str, detail: dict[str, Any]) -> AuditEntry:
        """Añade una entrada firmada a la cadena."""
        prev = self.entries[-1].entry_hash if self.entries else self.GENESIS
        entry = AuditEntry(
            index=len(self.entries),
            timestamp=datetime.now(tz=timezone.utc).isoformat(),
            actor=actor,
            action=action,
            detail=detail,
            prev_hash=prev,
        )
        entry.entry_hash = entry.compute_hash()
        self.entries.append(entry)
        with open(self.path, "a", encoding="utf-8") as fh:
            fh.write(json.dumps(asdict(entry), ensure_ascii=False) + "\n")
        return entry

    def verify(self) -> tuple[bool, int | None]:
        """
        Verifica la integridad de toda la cadena.
        Devuelve (True, None) si es íntegra, o (False, indice) del primer fallo.
        """
        prev = self.GENESIS
        for entry in self.entries:
            if entry.prev_hash != prev:
                return False, entry.index
            expected = entry.compute_hash()
            if expected != entry.entry_hash:
                return False, entry.index
            prev = entry.entry_hash
        return True, None
