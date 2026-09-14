"""
Registro de auditoría append-only con cadena de hashes verificable.

Cada entrada encadena el hash de la anterior. Sobre esa base, dos defensas que
una cadena SHA-256 desnuda no da:

1. **Firma con clave (HMAC-SHA256).** Sin clave, cualquiera que edite el archivo
   puede recalcular la cadena entera y la verificación pasa. Con clave, falsificar
   una entrada exige la clave, que vive fuera del archivo (variable de entorno
   `CYBERSENTINEL_AUDIT_KEY`).

2. **Anclaje externo** (`<archivo>.anchor`). La cadena por sí sola no detecta el
   truncado: si borras las últimas entradas, lo que queda sigue siendo una cadena
   válida. El ancla guarda cuántas entradas hay y cuál es el último hash, así que
   borrar el final se detecta.

Límite honesto que conviene declarar en la tesis: el ancla vive en el mismo disco.
Un atacante con permisos de escritura sobre ambos archivos **y** la clave puede
reescribirlo todo. La defensa completa exige publicar el ancla en un medio
independiente (otro host, almacenamiento WORM o un servicio de sellado de tiempo).
"""
from __future__ import annotations

import hashlib
import hmac
import json
import os
from dataclasses import dataclass, asdict
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

#: Variable de entorno de la que se lee la clave de firma.
AUDIT_KEY_ENV = "CYBERSENTINEL_AUDIT_KEY"


@dataclass
class AuditEntry:
    index: int
    timestamp: str
    actor: str            # "agent" | "human:<nombre>"
    action: str           # qué se registró
    detail: dict[str, Any]
    prev_hash: str
    entry_hash: str = ""
    algo: str = "sha256"  # "sha256" (sin clave) | "hmac-sha256" (firmada)

    def payload(self) -> str:
        """Representación canónica que se firma (orden estable de claves)."""
        return json.dumps(
            {
                "index": self.index,
                "timestamp": self.timestamp,
                "actor": self.actor,
                "action": self.action,
                "detail": self.detail,
                "prev_hash": self.prev_hash,
            },
            sort_keys=True,
            ensure_ascii=False,
        )

    def compute_hash(self, key: bytes | None = None) -> str:
        """Hash (o firma, si hay clave) de la entrada."""
        blob = self.payload().encode()
        if key:
            return hmac.new(key, blob, hashlib.sha256).hexdigest()
        return hashlib.sha256(blob).hexdigest()


class AuditLog:
    """Cadena de auditoría persistente en JSON Lines, con ancla externa."""

    GENESIS = "0" * 64

    def __init__(
        self,
        path: str | Path = "audit_log.jsonl",
        secret_key: str | bytes | None = None,
    ) -> None:
        """
        Si no se pasa `secret_key` se toma de `CYBERSENTINEL_AUDIT_KEY`. Sin
        clave el registro sigue funcionando en modo SHA-256 (detecta ediciones
        ingenuas, no una reescritura completa); `is_signed` lo indica.
        """
        self.path = Path(path)
        self.anchor_path = self.path.with_suffix(self.path.suffix + ".anchor")
        key = secret_key if secret_key is not None else os.environ.get(AUDIT_KEY_ENV)
        if isinstance(key, str):
            key = key.encode()
        self.key: bytes | None = key or None
        self.entries: list[AuditEntry] = []
        if self.path.exists():
            self._load()

    @property
    def is_signed(self) -> bool:
        """True si la cadena se firma con clave (HMAC) en lugar de solo hashearse."""
        return self.key is not None

    @property
    def algo(self) -> str:
        return "hmac-sha256" if self.is_signed else "sha256"

    def _load(self) -> None:
        with open(self.path, "r", encoding="utf-8") as fh:
            for line in fh:
                line = line.strip()
                if not line:
                    continue
                d = json.loads(line)
                known = {f for f in AuditEntry.__dataclass_fields__}
                self.entries.append(AuditEntry(**{k: v for k, v in d.items() if k in known}))

    def record(self, actor: str, action: str, detail: dict[str, Any]) -> AuditEntry:
        """Añade una entrada firmada a la cadena y actualiza el ancla."""
        prev = self.entries[-1].entry_hash if self.entries else self.GENESIS
        entry = AuditEntry(
            index=len(self.entries),
            timestamp=datetime.now(tz=timezone.utc).isoformat(),
            actor=actor,
            action=action,
            detail=detail,
            prev_hash=prev,
            algo=self.algo,
        )
        entry.entry_hash = entry.compute_hash(self.key)
        self.entries.append(entry)
        with open(self.path, "a", encoding="utf-8") as fh:
            fh.write(json.dumps(asdict(entry), ensure_ascii=False) + "\n")
        self._write_anchor()
        return entry

    # --- Ancla externa --------------------------------------------------------
    def _anchor_payload(self) -> dict[str, Any]:
        return {
            "entries": len(self.entries),
            "last_hash": self.entries[-1].entry_hash if self.entries else self.GENESIS,
            "algo": self.algo,
        }

    def _write_anchor(self) -> None:
        """Guarda (nº de entradas, último hash) fuera de la propia cadena."""
        anchor = self._anchor_payload()
        blob = json.dumps(anchor, sort_keys=True, ensure_ascii=False).encode()
        anchor["seal"] = (
            hmac.new(self.key, blob, hashlib.sha256).hexdigest() if self.key
            else hashlib.sha256(blob).hexdigest()
        )
        self.anchor_path.write_text(
            json.dumps(anchor, ensure_ascii=False, sort_keys=True), encoding="utf-8"
        )

    def _read_anchor(self) -> dict[str, Any] | None:
        if not self.anchor_path.exists():
            return None
        try:
            return json.loads(self.anchor_path.read_text(encoding="utf-8"))
        except json.JSONDecodeError:
            return None

    # --- Verificación ---------------------------------------------------------
    def verify(self) -> tuple[bool, int | None]:
        """
        Verifica la integridad de toda la cadena.

        Devuelve (True, None) si es íntegra, o (False, índice) del primer fallo.
        Cuando el fallo es del ancla (truncado o ancla manipulada) el índice es
        el de la primera entrada que falta, o -1 si el ancla no es coherente.
        """
        ok, idx, _ = self.verify_detailed()
        return ok, idx

    def verify_detailed(self) -> tuple[bool, int | None, str]:
        """Como `verify`, pero además explica en texto qué falló."""
        prev = self.GENESIS
        for entry in self.entries:
            if entry.prev_hash != prev:
                return False, entry.index, (
                    f"La entrada #{entry.index} no encadena con la anterior: "
                    "se insertó, reordenó o eliminó una entrada intermedia."
                )
            if entry.compute_hash(self.key) != entry.entry_hash:
                return False, entry.index, (
                    f"La entrada #{entry.index} fue alterada: su contenido no "
                    "corresponde con la firma registrada."
                )
            prev = entry.entry_hash

        anchor = self._read_anchor()
        if anchor is None:
            # Sin ancla no se puede descartar un truncado; se avisa, no se falla,
            # para no romper registros creados antes de existir el anclaje.
            return True, None, (
                "Cadena coherente. Sin archivo de ancla: no es posible descartar "
                "que se hayan eliminado entradas del final."
            )

        payload = {k: anchor.get(k) for k in ("entries", "last_hash", "algo")}
        blob = json.dumps(payload, sort_keys=True, ensure_ascii=False).encode()
        expected_seal = (
            hmac.new(self.key, blob, hashlib.sha256).hexdigest() if self.key
            else hashlib.sha256(blob).hexdigest()
        )
        if anchor.get("seal") != expected_seal:
            return False, -1, "El archivo de ancla fue manipulado."

        declared = int(anchor.get("entries", 0))
        if declared != len(self.entries):
            # Indice de la primera entrada discrepante: la primera que falta si
            # se truncó, o la primera sobrante si se añadieron entradas.
            first_bad = len(self.entries) if declared > len(self.entries) else declared
            return False, first_bad, (
                f"El ancla declara {declared} entradas y el registro tiene "
                f"{len(self.entries)}: se eliminaron o añadieron entradas."
            )
        if anchor.get("last_hash") != prev:
            return False, len(self.entries) - 1, (
                "El último hash no coincide con el anclado: el final de la "
                "cadena fue reescrito."
            )

        detail = "Cadena íntegra y anclada."
        if not self.is_signed:
            detail += (
                f" Aviso: sin clave de firma (define {AUDIT_KEY_ENV}), una "
                "reescritura completa del registro y del ancla no sería detectable."
            )
        return True, None, detail
