"""
Persistencia del resultado de cada evento procesado.

Se usa SQLite de la biblioteca estándar: no añade dependencias y, a diferencia
de un JSONL, permite consultar (¿qué detectó la regla X esta semana?, ¿qué
eventos de este `run_id` superaron el umbral?) sin releer el archivo entero.

Guarda **lo que el analista necesita para decidir**, no la evidencia completa:
la evidencia íntegra puede ocupar cientos de KB por evento —ya se midió: 20 000
eventos generaban 129 MB de JSON— y no cabe en un almacén por evento. Aquí va el
resumen consultable; la evidencia completa se reconstruye desde `run_id` y
`event_ref`.
"""
from __future__ import annotations

import json
import logging
import sqlite3
import threading
from contextlib import closing
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

logger = logging.getLogger(__name__)

ESQUEMA = """
CREATE TABLE IF NOT EXISTS processed_events (
    id             INTEGER PRIMARY KEY AUTOINCREMENT,
    run_id         TEXT    NOT NULL,
    event_id       TEXT    NOT NULL,
    event_ref      TEXT    NOT NULL,
    event_time     TEXT    NOT NULL,
    ingested_at    TEXT    NOT NULL,
    source         TEXT    NOT NULL,
    entity         TEXT,
    result         TEXT    NOT NULL,   -- detection_status
    score          REAL    NOT NULL,   -- hybrid_score
    anomaly_score  REAL    NOT NULL,
    rules_fired    TEXT,               -- JSON: ["RULE-0002", ...]
    attack_techniques TEXT,            -- JSON: ["T1059", ...]
    attack_tactics TEXT,               -- JSON
    cti_matches    INTEGER NOT NULL DEFAULT 0,
    incident_id    TEXT,               -- presente solo si supero el umbral
    llm_status     TEXT,
    fallback_used  INTEGER NOT NULL DEFAULT 0
);
CREATE INDEX IF NOT EXISTS idx_run     ON processed_events(run_id);
CREATE INDEX IF NOT EXISTS idx_result  ON processed_events(result);
CREATE INDEX IF NOT EXISTS idx_time    ON processed_events(event_time);
CREATE INDEX IF NOT EXISTS idx_incident ON processed_events(incident_id);
"""


class ResultStore:
    """Almacén consultable del resultado de cada evento."""

    def __init__(self, path: str | Path) -> None:
        self.path = Path(path)
        self.path.parent.mkdir(parents=True, exist_ok=True)
        self._lock = threading.Lock()
        with closing(self._connect()) as con:
            con.executescript(ESQUEMA)
            con.commit()

    def _connect(self) -> sqlite3.Connection:
        con = sqlite3.connect(self.path, timeout=30)
        con.row_factory = sqlite3.Row
        return con

    def save_batch(self, resultados: list[Any], umbral: float) -> int:
        """
        Persiste el resultado de un lote.

        `incident_id` solo se rellena cuando el evento superó el umbral de
        alerta: un evento analizado no es un incidente, y confundirlos inflaría
        la cuenta de incidentes del producto.
        """
        ahora = datetime.now(tz=timezone.utc).isoformat(timespec="milliseconds")
        filas = []
        for r in resultados:
            e = r.evidence
            es_incidente = e.hybrid_score >= umbral
            filas.append((
                e.run_id, e.event_id, e.event_ref,
                e.created_at, ahora,
                getattr(r, "source", None) or "desconocida",
                e.entity or None,
                e.detection_status,
                float(e.hybrid_score), float(e.anomaly_score),
                json.dumps([h.rule.id for h in e.rule_matches], ensure_ascii=False),
                json.dumps(e.mitre_context, ensure_ascii=False),
                json.dumps(e.mitre_tactics, ensure_ascii=False),
                len(e.cti_hits),
                f"{e.run_id}:{e.event_ref}" if es_incidente else None,
                e.llm_status,
                int(e.fallback_used),
            ))

        with self._lock, closing(self._connect()) as con:
            con.executemany(
                "INSERT INTO processed_events (run_id, event_id, event_ref, "
                "event_time, ingested_at, source, entity, result, score, "
                "anomaly_score, rules_fired, attack_techniques, attack_tactics, "
                "cti_matches, incident_id, llm_status, fallback_used) "
                "VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)", filas,
            )
            con.commit()
        return len(filas)

    # --- Consultas --------------------------------------------------------
    def count(self) -> int:
        with closing(self._connect()) as con:
            return con.execute("SELECT COUNT(*) FROM processed_events").fetchone()[0]

    def incidents(self, limit: int = 50) -> list[dict[str, Any]]:
        with closing(self._connect()) as con:
            filas = con.execute(
                "SELECT * FROM processed_events WHERE incident_id IS NOT NULL "
                "ORDER BY score DESC LIMIT ?", (limit,),
            ).fetchall()
        return [dict(f) for f in filas]

    def summary(self) -> dict[str, Any]:
        with closing(self._connect()) as con:
            total = con.execute("SELECT COUNT(*) FROM processed_events").fetchone()[0]
            por_resultado = dict(con.execute(
                "SELECT result, COUNT(*) FROM processed_events GROUP BY result"
            ).fetchall())
            incidentes = con.execute(
                "SELECT COUNT(*) FROM processed_events WHERE incident_id IS NOT NULL"
            ).fetchone()[0]
            con_regla = con.execute(
                "SELECT COUNT(*) FROM processed_events WHERE rules_fired != '[]'"
            ).fetchone()[0]
            score_max = con.execute(
                "SELECT MAX(score) FROM processed_events"
            ).fetchone()[0]
        return {
            "total_events": total,
            "by_result": por_resultado,
            "incidents": incidentes,
            "events_with_rule_match": con_regla,
            "max_score": score_max,
            "db_path": str(self.path),
            "db_size_bytes": self.path.stat().st_size if self.path.exists() else 0,
        }
