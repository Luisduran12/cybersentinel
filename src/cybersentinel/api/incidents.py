"""
El incidente como entidad persistente, con ciclo de vida y cronología.

Hasta aquí, el sistema producía **resultados efímeros**: `ResultStore` guardaba
un resumen consultable por evento —puntuación, reglas, técnicas— y la evidencia
completa se perdía al terminar el proceso. Para medir detección eso basta. Para
investigar no: un analista que abre una alerta necesita saber *por qué* saltó
—qué regla, con qué extracto, sobre qué evento crudo— y necesita poder decir
«esto lo llevo yo» y «esto es un falso positivo» sin que la siguiente ejecución
lo borre.

Tres decisiones y su motivo:

1. **Solo lo que superó el umbral guarda evidencia completa.** Ya se midió que
   volcar la evidencia íntegra de 20 000 eventos produce 129 MB de JSON. Un
   incidente es una fracción pequeña del caudal, así que aquí sí cabe; el
   resumen por evento sigue en `ResultStore`, que es quien responde «¿cuántos
   eventos vi?». Confundir ambas cosas infla la cuenta de incidentes del
   producto.

2. **La cronología es de solo-añadir.** Cambiar de estado, asignar, anotar y
   decidir escriben una entrada nueva; nada se sobrescribe. El estado actual es
   una columna por comodidad de consulta, pero la verdad está en la cronología.
   Un panel que deja reescribir la historia no sirve como registro de una
   investigación.

3. **Las transiciones son explícitas.** Un ciclo de vida que acepta cualquier
   cambio no es un ciclo de vida, es un campo de texto. Aquí `cerrado → en
   curso` exige reabrir, y cerrar exige una resolución.

**Lo que esto NO hace, y conviene decirlo:** un incidente por evento que cruzó
el umbral. No agrupa una campaña en un solo incidente. El correlador temporal
existe y alimenta la evidencia, pero la agrupación de eventos en un incidente
único es un trabajo aparte que no se ha hecho: en una cadena de ataque de ocho
pasos, el analista verá ocho incidentes relacionados por entidad y ventana, no
uno.
"""
from __future__ import annotations

import json
import logging
import sqlite3
import threading
from contextlib import closing
from dataclasses import dataclass
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

from ..config import DEFAULT_ANOMALY_THRESHOLD

logger = logging.getLogger(__name__)

#: Estados del ciclo de vida. Cortos y en número mínimo: cada estado que nadie
#: sabe explicar es un estado en el que los incidentes se quedan atascados.
ESTADOS = ("new", "triaged", "confirmed", "false_positive", "uncertain", "resolved")

#: Transiciones permitidas. Lo que no está aquí se rechaza con un error que
#: dice qué sí se puede hacer.
TRANSICIONES: dict[str, tuple[str, ...]] = {
    "new": ("triaged", "confirmed", "false_positive", "uncertain", "resolved"),
    "triaged": ("confirmed", "false_positive", "uncertain", "resolved", "new"),
    "confirmed": ("resolved", "triaged"),
    "false_positive": ("resolved", "triaged"),
    "uncertain": ("resolved", "triaged"),
    "resolved": ("triaged",),   # reabrir vuelve a triaje
}

#: Motivos de cierre. Cerrar sin uno deja un incidente que no enseña nada:
#: ni al analista siguiente, ni al dataset de reentrenamiento.
RESOLUCIONES = ("true_positive", "false_positive", "benign", "duplicate")

#: Severidad derivada de la puntuación híbrida. Es una traducción, no una señal
#: nueva: el panel necesita ordenar por urgencia y «73,4» no ordena a la vista.
UMBRALES_SEVERIDAD = ((85.0, "critical"), (70.0, "high"), (55.0, "medium"))

#: Topes de tamaño. Sin ellos, una narrativa larga o un evento crudo enorme
#: convierten la base del panel en el problema que la base de eventos ya tuvo.
MAX_NARRATIVA = 8_000
MAX_JSON = 32_000

ESQUEMA = """
CREATE TABLE IF NOT EXISTS incidents (
    incident_id   TEXT PRIMARY KEY,      -- "<run_id>:<event_ref>"
    run_id        TEXT NOT NULL,
    event_ref     TEXT NOT NULL,
    event_id      TEXT NOT NULL,
    title         TEXT NOT NULL,
    event_time    TEXT NOT NULL,         -- cuándo pasó
    detected_at   TEXT NOT NULL,         -- cuándo lo vimos
    updated_at    TEXT NOT NULL,
    source        TEXT NOT NULL,
    entity        TEXT,
    host          TEXT,
    username      TEXT,
    severity      TEXT NOT NULL,
    score         REAL NOT NULL,
    anomaly_score REAL NOT NULL,
    detection_status TEXT NOT NULL,
    state         TEXT NOT NULL DEFAULT 'new',
    owner         TEXT,
    resolution    TEXT,
    closed_at     TEXT,
    techniques    TEXT NOT NULL DEFAULT '[]',
    tactics       TEXT NOT NULL DEFAULT '[]',
    rules         TEXT NOT NULL DEFAULT '[]',
    cti           TEXT NOT NULL DEFAULT '[]',
    rag           TEXT NOT NULL DEFAULT '[]',
    recommendations TEXT NOT NULL DEFAULT '[]',
    raw_event     TEXT NOT NULL DEFAULT '{}',
    narrative     TEXT NOT NULL DEFAULT '',
    llm_status    TEXT,
    fallback_used INTEGER NOT NULL DEFAULT 0
);
CREATE INDEX IF NOT EXISTS idx_inc_state    ON incidents(state);
CREATE INDEX IF NOT EXISTS idx_inc_severity ON incidents(severity);
CREATE INDEX IF NOT EXISTS idx_inc_owner    ON incidents(owner);
CREATE INDEX IF NOT EXISTS idx_inc_entity   ON incidents(entity);
CREATE INDEX IF NOT EXISTS idx_inc_detected ON incidents(detected_at);

CREATE TABLE IF NOT EXISTS incident_timeline (
    id          INTEGER PRIMARY KEY AUTOINCREMENT,
    incident_id TEXT NOT NULL,
    at          TEXT NOT NULL,
    actor       TEXT NOT NULL,
    kind        TEXT NOT NULL,   -- created|state|owner|severity|note|decision
    text        TEXT NOT NULL DEFAULT '',
    payload     TEXT NOT NULL DEFAULT '{}',
    FOREIGN KEY (incident_id) REFERENCES incidents(incident_id)
);
CREATE INDEX IF NOT EXISTS idx_tl_incident ON incident_timeline(incident_id, id);
"""


class IncidentError(Exception):
    """Operación inválida sobre un incidente (transición, campo o resolución)."""


def _ahora() -> str:
    return datetime.now(tz=timezone.utc).isoformat(timespec="seconds")


def _json(valor: Any, tope: int = MAX_JSON) -> str:
    texto = json.dumps(valor, ensure_ascii=False, default=str)
    if len(texto) <= tope:
        return texto
    # Truncar de forma visible: un JSON recortado en silencio es peor que uno
    # que declara que se recortó.
    return json.dumps({"truncated": True, "original_bytes": len(texto),
                       "preview": texto[:tope]}, ensure_ascii=False)


def severidad_de(score: float) -> str:
    for minimo, etiqueta in UMBRALES_SEVERIDAD:
        if score >= minimo:
            return etiqueta
    return "low"


def _narrativa(resultado: Any, evidencia: Any) -> tuple[str, bool]:
    """
    Garantiza que el incidente lleve un porqué legible.

    El pipeline deja la narrativa vacía cuando el explicador está desactivado
    —`enable_llm=False` significa «no llames a un modelo», y eso se respeta—.
    Pero un incidente sin explicación no se puede investigar: el analista ve una
    puntuación y ninguna frase que diga qué la produjo.

    La solución no es llamar a un modelo por la puerta de atrás, sino usar el
    redactor determinista que ya existe: no inventa nada, describe la evidencia
    y declara lo que no aportó nada. Se devuelve además si hubo que recurrir a
    él, para que el panel pueda decirlo en lugar de hacer pasar un texto
    generado por plantilla por una explicación de modelo.
    """
    texto = (getattr(resultado, "narrative", "") or "").strip()
    if texto:
        return texto, False
    try:
        from ..llm.providers import deterministic_explanation

        return deterministic_explanation(evidencia), True
    except Exception:
        logger.exception("No se pudo redactar la explicación determinista")
        return "", True


def _titulo(evidencia: Any, evento: Any) -> str:
    """
    Título legible del incidente.

    Se construye de lo que efectivamente disparó —la regla— y sobre quién. Un
    título genérico («Incidente 47») obliga a abrir cada tarjeta para saber si
    merece atención, que es justo lo que un panel debe evitar.
    """
    if evidencia.rule_matches:
        base = evidencia.rule_matches[0].rule.title
    elif evidencia.anomaly_score >= DEFAULT_ANOMALY_THRESHOLD:
        base = "Anomalía sin regla asociada"
    else:
        base = "Detección"
    donde = evidencia.entity or getattr(evento, "host", None) or "entidad desconocida"
    return f"{base} · {donde}"[:200]


@dataclass
class Filtro:
    """Criterios de la lista del panel. Todos opcionales y combinables."""

    state: str | None = None
    severity: str | None = None
    owner: str | None = None
    entity: str | None = None
    technique: str | None = None
    unassigned: bool = False
    query: str | None = None
    since: str | None = None
    limit: int = 50
    offset: int = 0


class IncidentStore:
    """Incidentes con estado, propietario y cronología, en SQLite."""

    def __init__(self, path: str | Path) -> None:
        self.path = Path(path)
        self.path.parent.mkdir(parents=True, exist_ok=True)
        self._lock = threading.Lock()
        self._local = threading.local()
        with closing(self._connect()) as con:
            con.executescript(ESQUEMA)
            con.commit()

    def _connect(self) -> sqlite3.Connection:
        con = sqlite3.connect(self.path, timeout=30)
        con.row_factory = sqlite3.Row
        # Modo WAL: varios procesos pueden leer mientras uno escribe. Sin él,
        # SQLite serializa con un candado global de base de datos y dos réplicas
        # sobre el mismo archivo se bloquean entre sí en cuanto hay tráfico.
        # `busy_timeout` es lo que convierte una colisión en una espera corta en
        # lugar de en un «database is locked» que sube hasta el cliente.
        con.execute("PRAGMA journal_mode=WAL")
        con.execute("PRAGMA busy_timeout=10000")
        # `synchronous=NORMAL` es lo recomendado con WAL: la durabilidad real de
        # lo aceptado la da el registro anticipado, no esta base.
        con.execute("PRAGMA synchronous=NORMAL")
        return con

    def _reader(self) -> sqlite3.Connection:
        con = getattr(self._local, "con", None)
        if con is None:
            con = self._connect()
            self._local.con = con
        return con

    # --- Alta -------------------------------------------------------------
    def save_batch(self, resultados: list[Any], umbral: float,
                   eventos_por_ref: dict[str, Any] | None = None) -> int:
        """
        Crea un incidente por cada resultado que superó el umbral.

        `INSERT OR IGNORE`: reprocesar el mismo lote no duplica incidentes ni
        pisa el trabajo del analista. La clave es `event_id`, la misma que
        `ResultStore` usa como `incident_id`, para garantizar la idempotencia.
        """
        eventos_por_ref = eventos_por_ref or {}
        ahora = _ahora()
        filas, cronologia = [], []

        for r in resultados:
            e = r.evidence
            if e.hybrid_score < umbral:
                continue
            incident_id = e.event_id
            evento = eventos_por_ref.get(e.event_ref)
            crudo = evento.to_dict() if evento is not None and hasattr(evento, "to_dict") else {}
            narrativa, sin_modelo = _narrativa(r, e)

            filas.append((
                incident_id, e.run_id, e.event_ref, e.event_id,
                _titulo(e, evento), e.created_at, ahora, ahora,
                getattr(r, "source", None) or (crudo.get("source") if crudo else None) or "desconocida",
                e.entity or None, crudo.get("host"), crudo.get("user"),
                severidad_de(e.hybrid_score), float(e.hybrid_score), float(e.anomaly_score),
                e.detection_status, "new", None, None, None,
                _json(e.mitre_context), _json(e.mitre_tactics),
                _json([h.to_dict() for h in e.rule_matches]),
                _json([c.to_dict() for c in e.cti_hits]),
                _json([c.to_dict() for c in e.rag_context]),
                _json([rec.to_dict() for rec in getattr(r, "recommendations", [])]),
                _json(crudo), narrativa[:MAX_NARRATIVA],
                e.llm_status, int(e.fallback_used or sin_modelo),
            ))
            cronologia.append((
                incident_id, ahora, "agent", "created",
                f"Detectado por el pipeline con puntuación {e.hybrid_score:.1f}",
                _json({"detection_status": e.detection_status,
                       "rules": [h.rule.id for h in e.rule_matches],
                       "techniques": e.mitre_context}),
            ))

        if not filas:
            return 0

        with self._lock, closing(self._connect()) as con:
            cur = con.executemany(
                "INSERT OR IGNORE INTO incidents VALUES (" + ",".join(["?"] * 30) + ")", filas)
            creados = cur.rowcount
            # La cronología solo para los realmente creados: si el incidente ya
            # existía, añadir otro «creado» falsearía su historia.
            existentes = {f[0] for f in con.execute(
                "SELECT incident_id FROM incident_timeline WHERE kind = 'created'"
            ).fetchall()}
            con.executemany(
                "INSERT INTO incident_timeline (incident_id, at, actor, kind, text, payload) "
                "VALUES (?,?,?,?,?,?)",
                [c for c in cronologia if c[0] not in existentes],
            )
            con.commit()
        return max(creados, 0)

    # --- Consulta ---------------------------------------------------------
    RESUMEN = ("incident_id, title, event_time, detected_at, updated_at, source, "
               "entity, host, username, severity, score, detection_status, state, "
               "owner, resolution, techniques, tactics")

    def list(self, filtro: Filtro) -> dict[str, Any]:
        condiciones, parametros = [], []
        if filtro.state:
            condiciones.append("state = ?"); parametros.append(filtro.state)
        if filtro.severity:
            condiciones.append("severity = ?"); parametros.append(filtro.severity)
        if filtro.owner:
            condiciones.append("owner = ?"); parametros.append(filtro.owner)
        if filtro.unassigned:
            condiciones.append("owner IS NULL")
        if filtro.entity:
            condiciones.append("entity = ?"); parametros.append(filtro.entity)
        if filtro.technique:
            # Búsqueda sobre el JSON de técnicas. Es un LIKE, no un índice: con
            # el volumen de un panel (miles, no millones) es suficiente, y está
            # dicho aquí para que nadie lo descubra midiendo.
            condiciones.append("techniques LIKE ?"); parametros.append(f'%"{filtro.technique}"%')
        if filtro.since:
            condiciones.append("detected_at >= ?"); parametros.append(filtro.since)
        if filtro.query:
            condiciones.append("(title LIKE ? OR entity LIKE ? OR host LIKE ? "
                               "OR username LIKE ? OR incident_id LIKE ?)")
            parametros.extend([f"%{filtro.query}%"] * 5)

        donde = (" WHERE " + " AND ".join(condiciones)) if condiciones else ""
        limite = max(1, min(filtro.limit, 200))
        con = self._reader()
        total = con.execute(f"SELECT COUNT(*) FROM incidents{donde}", parametros).fetchone()[0]
        filas = con.execute(
            f"SELECT {self.RESUMEN} FROM incidents{donde} "
            # Sin estado antes que cerrado, y dentro de eso lo más grave y
            # reciente primero: el orden por defecto de un panel es una
            # decisión de producto, no un detalle.
            "ORDER BY CASE state WHEN 'resolved' THEN 1 ELSE 0 END, "
            "CASE severity WHEN 'critical' THEN 0 WHEN 'high' THEN 1 "
            "WHEN 'medium' THEN 2 ELSE 3 END, detected_at DESC "
            "LIMIT ? OFFSET ?", [*parametros, limite, max(0, filtro.offset)],
        ).fetchall()

        return {
            "total": total, "limit": limite, "offset": max(0, filtro.offset),
            "incidents": [self._resumen(f) for f in filas],
        }

    @staticmethod
    def _resumen(fila: sqlite3.Row) -> dict[str, Any]:
        d = dict(fila)
        for campo in ("techniques", "tactics"):
            d[campo] = json.loads(d.get(campo) or "[]")
        d["score"] = round(d["score"], 2)
        return d

    def get(self, incident_id: str) -> dict[str, Any] | None:
        con = self._reader()
        fila = con.execute("SELECT * FROM incidents WHERE incident_id = ?",
                           (incident_id,)).fetchone()
        if fila is None:
            return None
        d = dict(fila)
        for campo in ("techniques", "tactics", "rules", "cti", "rag",
                      "recommendations", "raw_event"):
            try:
                d[campo] = json.loads(d.get(campo) or "[]")
            except json.JSONDecodeError:
                d[campo] = []
        d["fallback_used"] = bool(d["fallback_used"])
        d["score"] = round(d["score"], 2)
        d["timeline"] = self.timeline(incident_id)
        return d

    def timeline(self, incident_id: str) -> list[dict[str, Any]]:
        filas = self._reader().execute(
            "SELECT at, actor, kind, text, payload FROM incident_timeline "
            "WHERE incident_id = ? ORDER BY id", (incident_id,)).fetchall()
        salida = []
        for f in filas:
            d = dict(f)
            try:
                d["payload"] = json.loads(d["payload"] or "{}")
            except json.JSONDecodeError:
                d["payload"] = {}
            salida.append(d)
        return salida

    def stats(self) -> dict[str, Any]:
        """Las cifras de cabecera del panel, calculadas, no estimadas."""
        con = self._reader()
        por_estado = dict(con.execute(
            "SELECT state, COUNT(*) FROM incidents GROUP BY state").fetchall())
        por_severidad = dict(con.execute(
            "SELECT severity, COUNT(*) FROM incidents GROUP BY severity").fetchall())
        por_resolucion = dict(con.execute(
            "SELECT resolution, COUNT(*) FROM incidents WHERE resolution IS NOT NULL "
            "GROUP BY resolution").fetchall())
        abiertos = con.execute(
            "SELECT COUNT(*) FROM incidents WHERE state != 'resolved'").fetchone()[0]
        sin_duenno = con.execute(
            "SELECT COUNT(*) FROM incidents WHERE owner IS NULL AND state != 'resolved'"
        ).fetchone()[0]
        criticos = con.execute(
            "SELECT COUNT(*) FROM incidents WHERE severity = 'critical' AND state != 'resolved'"
        ).fetchone()[0]
        tecnicas = con.execute(
            "SELECT techniques FROM incidents WHERE techniques != '[]' LIMIT 2000").fetchall()

        cuenta: dict[str, int] = {}
        for (blob,) in tecnicas:
            try:
                for t in json.loads(blob):
                    cuenta[t] = cuenta.get(t, 0) + 1
            except json.JSONDecodeError:
                continue

        return {
            "total": sum(por_estado.values()),
            "open": abiertos,
            "unassigned": sin_duenno,
            "critical_open": criticos,
            "by_state": por_estado,
            "by_severity": por_severidad,
            "by_resolution": por_resolucion,
            "top_techniques": sorted(cuenta.items(), key=lambda kv: -kv[1])[:10],
        }

    # --- Ciclo de vida ----------------------------------------------------
    def update(self, incident_id: str, actor: str, *, state: str | None = None,
               owner: str | None = None, severity: str | None = None,
               resolution: str | None = None, note: str = "",
               clear_owner: bool = False) -> dict[str, Any]:
        """
        Cambia estado, propietario o severidad, y lo deja escrito.

        Valida la transición antes de tocar nada: un ciclo de vida que acepta
        cualquier cambio no es un ciclo de vida.
        """
        actual = self.get(incident_id)
        if actual is None:
            raise IncidentError(f"no existe el incidente {incident_id}")

        cambios: list[tuple[str, Any]] = []
        entradas: list[tuple[str, str, str, dict[str, Any]]] = []
        ahora = _ahora()

        if state is not None:
            if state not in ESTADOS:
                raise IncidentError(f"estado desconocido {state!r}; válidos: {list(ESTADOS)}")
            if state != actual["state"]:
                permitidos = TRANSICIONES.get(actual["state"], ())
                if state not in permitidos:
                    raise IncidentError(
                        f"no se puede pasar de {actual['state']!r} a {state!r}; "
                        f"desde {actual['state']!r} solo: {list(permitidos)}")
                if state == "resolved":
                    if resolution not in RESOLUCIONES:
                        raise IncidentError(
                            "cerrar exige una resolución válida: "
                            f"{list(RESOLUCIONES)}")
                    cambios += [("resolution", resolution), ("closed_at", ahora)]
                elif actual["state"] == "resolved":
                    # Reabrir limpia la resolución: dejarla puesta haría creer
                    # que un incidente abierto ya está concluido.
                    cambios += [("resolution", None), ("closed_at", None)]
                cambios.append(("state", state))
                entradas.append(("state", f"{actual['state']} → {state}", actor,
                                 {"from": actual["state"], "to": state,
                                  "resolution": resolution}))

        if clear_owner:
            if actual["owner"] is not None:
                cambios.append(("owner", None))
                entradas.append(("owner", f"sin propietario (antes {actual['owner']})",
                                 actor, {"from": actual["owner"], "to": None}))
        elif owner is not None and owner != actual["owner"]:
            cambios.append(("owner", owner))
            entradas.append(("owner", f"asignado a {owner}", actor,
                             {"from": actual["owner"], "to": owner}))

        if severity is not None and severity != actual["severity"]:
            if severity not in {s for _, s in UMBRALES_SEVERIDAD} | {"low"}:
                raise IncidentError(f"severidad desconocida {severity!r}")
            cambios.append(("severity", severity))
            # Se registra que la severidad la puso una persona: sin esta marca,
            # nadie sabría después si la ordenación del panel refleja el modelo
            # o el criterio de un analista.
            entradas.append(("severity", f"severidad {actual['severity']} → {severity} "
                                         f"(ajustada por una persona)", actor,
                             {"from": actual["severity"], "to": severity,
                              "derived_from_score": severidad_de(actual["score"])}))

        if note:
            entradas.append(("note", note[:4000], actor, {}))

        if not cambios and not entradas:
            return actual

        with self._lock, closing(self._connect()) as con:
            if cambios:
                asignaciones = ", ".join(f"{c} = ?" for c, _ in cambios)
                con.execute(
                    f"UPDATE incidents SET {asignaciones}, updated_at = ? WHERE incident_id = ?",
                    [*(v for _, v in cambios), ahora, incident_id])
            con.executemany(
                "INSERT INTO incident_timeline (incident_id, at, actor, kind, text, payload) "
                "VALUES (?,?,?,?,?,?)",
                [(incident_id, ahora, quien, clase, texto, _json(extra))
                 for clase, texto, quien, extra in entradas])
            con.commit()

        return self.get(incident_id)  # type: ignore[return-value]

    def add_note(self, incident_id: str, actor: str, texto: str) -> dict[str, Any]:
        if not texto.strip():
            raise IncidentError("la nota no puede estar vacía")
        return self.update(incident_id, actor, note=texto.strip())

    def record_decision(self, incident_id: str, actor: str, decision: str,
                        reason: str, fingerprint: str) -> None:
        """Deja la decisión HITL también en la cronología del incidente."""
        ahora = _ahora()
        with self._lock, closing(self._connect()) as con:
            con.execute(
                "INSERT INTO incident_timeline (incident_id, at, actor, kind, text, payload) "
                "VALUES (?,?,?,?,?,?)",
                (incident_id, ahora, actor, "decision",
                 f"Decisión del analista: {decision}",
                 _json({"decision": decision, "reason": reason,
                        "fingerprint": fingerprint})))
            con.execute("UPDATE incidents SET updated_at = ? WHERE incident_id = ?",
                        (ahora, incident_id))
            con.commit()

    def summary(self) -> dict[str, Any]:
        return {**self.stats(), "db_path": str(self.path),
                "db_size_bytes": self.path.stat().st_size if self.path.exists() else 0}
