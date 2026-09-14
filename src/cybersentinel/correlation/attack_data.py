"""
Carga de la matriz MITRE ATT&CK oficial desde el STIX empresarial.

El proyecto traía un subconjunto de ATT&CK escrito a mano. Funcionaba, pero
quedó desfasado: MITRE dividió la táctica `defense-evasion` en `stealth` y
`defense-impairment`, revocó técnicas y la matriz pasó de 14 a 15 fases. Este
módulo sustituye ese subconjunto por los datos oficiales.

Tres capas, de más a menos preferida
------------------------------------
1. **Caché compacta** (`data/attack/attack_cache.json`, ~200 KB): lo que se usa
   en cada ejecución. Se versiona con el proyecto.
2. **STIX oficial** (`enterprise-attack.json`, ~51 MB): la fuente de verdad, de
   la que se genera la caché con `cybersentinel attack-sync`.
3. **Subconjunto embebido** (`mitre.py`): el respaldo. Si no hay caché ni STIX,
   el sistema sigue funcionando con las técnicas que usan las reglas propias.

Por qué la caché existe
-----------------------
Cargar el STIX con `mitreattack-python` tarda unos 13 segundos y exige 51 MB en
disco más una dependencia pesada. Eso es aceptable una vez, no en cada análisis.
La caché guarda solo lo que el pipeline consulta —identificador, nombre, tácticas
y relación con la técnica madre— y hace que el proyecto arranque sin la librería
ni el bundle, algo que importa cuando el tribunal clona el repositorio.

Se usa `mitreattack-python` cuando está instalada; si no, se interpreta el STIX
directamente, que es JSON plano. Así la dependencia es real pero no obligatoria.
"""
from __future__ import annotations

import json
import logging
from dataclasses import dataclass, field
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

logger = logging.getLogger(__name__)

ROOT = Path(__file__).resolve().parents[3]
DEFAULT_STIX_PATH = ROOT / "data" / "attack" / "enterprise-attack.json"
DEFAULT_CACHE_PATH = ROOT / "data" / "attack" / "attack_cache.json"

#: Tácticas renombradas por MITRE. Permite que reglas y corpus antiguos sigan
#: resolviendo: `defense-evasion` dejó de existir al dividirse en dos.
TACTIC_ALIASES: dict[str, str] = {
    "defense-evasion": "stealth",
    "defence-evasion": "stealth",
}


@dataclass
class Technique:
    """Una técnica o subtécnica de ATT&CK."""
    id: str                       # "T1059" o "T1059.001"
    name: str
    tactics: list[str] = field(default_factory=list)   # puede pertenecer a varias
    is_subtechnique: bool = False
    parent: str | None = None

    def to_dict(self) -> dict[str, Any]:
        data: dict[str, Any] = {"name": self.name, "tactics": self.tactics}
        if self.is_subtechnique:
            data["parent"] = self.parent
        return data


@dataclass
class AttackData:
    """Matriz ATT&CK lista para consultar."""
    techniques: dict[str, Technique] = field(default_factory=dict)
    tactic_order: list[str] = field(default_factory=list)
    tactic_names: dict[str, str] = field(default_factory=dict)
    version: str = "desconocida"
    generated_at: str = ""
    source: str = "embebido"

    # --- Consultas ------------------------------------------------------------
    def technique(self, technique_id: str) -> Technique | None:
        """
        Busca una técnica, cayendo a la técnica madre si es una subtécnica.

        Las reglas propias citan `T1059`, pero la telemetría real y los datasets
        citan `T1059.001`. Sin este respaldo, media matriz no resolvería.
        """
        found = self.techniques.get(technique_id)
        if found is not None:
            return found
        if "." in technique_id:
            return self.techniques.get(technique_id.split(".", 1)[0])
        return None

    def tactics_of(self, technique_id: str) -> list[str]:
        """Todas las tácticas a las que pertenece la técnica."""
        found = self.technique(technique_id)
        return list(found.tactics) if found else []

    def primary_tactic(self, technique_id: str) -> str:
        """
        Una sola táctica, para los usos que necesitan un valor escalar.

        Se elige la **más temprana** de la cadena. Una técnica como
        `T1053` (Scheduled Task/Job) pertenece a ejecución, persistencia y
        escalada de privilegios a la vez; tomar la más temprana evita que un
        único hallazgo haga parecer que el ataque está más avanzado de lo que
        demuestra la evidencia.
        """
        tactics = self.tactics_of(technique_id)
        if not tactics:
            return "unknown"
        known = [t for t in tactics if t in self.tactic_order]
        if not known:
            return tactics[0]
        return min(known, key=self.tactic_order.index)

    def normalize_tactic(self, tactic: str) -> str:
        """Traduce un nombre de táctica retirado a su equivalente vigente."""
        if tactic in self.tactic_order:
            return tactic
        return TACTIC_ALIASES.get(tactic, tactic)

    @property
    def n_techniques(self) -> int:
        return sum(1 for t in self.techniques.values() if not t.is_subtechnique)

    @property
    def n_subtechniques(self) -> int:
        return sum(1 for t in self.techniques.values() if t.is_subtechnique)

    # --- Persistencia ---------------------------------------------------------
    def to_dict(self) -> dict[str, Any]:
        return {
            "version": self.version,
            "generated_at": self.generated_at,
            "source": self.source,
            "tactic_order": self.tactic_order,
            "tactic_names": self.tactic_names,
            "techniques": {tid: t.to_dict() for tid, t in sorted(self.techniques.items())},
        }

    def save(self, path: str | Path = DEFAULT_CACHE_PATH) -> Path:
        path = Path(path)
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(
            json.dumps(self.to_dict(), indent=1, ensure_ascii=False, sort_keys=False),
            encoding="utf-8",
        )
        return path

    @classmethod
    def from_dict(cls, data: dict[str, Any]) -> "AttackData":
        techniques = {}
        for tid, raw in data.get("techniques", {}).items():
            techniques[tid] = Technique(
                id=tid,
                name=raw.get("name", tid),
                tactics=list(raw.get("tactics", [])),
                is_subtechnique="." in tid,
                parent=raw.get("parent") or (tid.split(".", 1)[0] if "." in tid else None),
            )
        return cls(
            techniques=techniques,
            tactic_order=list(data.get("tactic_order", [])),
            tactic_names=dict(data.get("tactic_names", {})),
            version=data.get("version", "desconocida"),
            generated_at=data.get("generated_at", ""),
            source=data.get("source", "cache"),
        )

    @classmethod
    def load(cls, path: str | Path = DEFAULT_CACHE_PATH) -> "AttackData | None":
        """Carga la caché. Devuelve None si no existe o está corrupta."""
        path = Path(path)
        if not path.exists():
            return None
        try:
            return cls.from_dict(json.loads(path.read_text(encoding="utf-8")))
        except (json.JSONDecodeError, TypeError, KeyError) as exc:
            logger.warning("Cache ATT&CK ilegible en %s: %s", path, exc)
            return None


# --- Construcción desde el STIX oficial ---------------------------------------
def _attack_id(stix_object: dict[str, Any]) -> str | None:
    """Extrae el identificador ATT&CK (T####) de las referencias externas."""
    for reference in stix_object.get("external_references", []):
        if reference.get("source_name") == "mitre-attack":
            return reference.get("external_id")
    return None


def _is_active(stix_object: dict[str, Any]) -> bool:
    return not (stix_object.get("revoked") or stix_object.get("x_mitre_deprecated"))


def build_from_stix(path: str | Path = DEFAULT_STIX_PATH) -> AttackData:
    """
    Construye la matriz desde el bundle STIX oficial de MITRE.

    Usa `mitreattack-python` si está instalada; si no, interpreta el JSON
    directamente. El resultado es idéntico: la librería aporta comodidad, no
    datos distintos.
    """
    path = Path(path)
    if not path.exists():
        raise FileNotFoundError(
            f"No existe el STIX de ATT&CK en {path}. Descárgalo con:\n"
            "  curl -sSL -o data/attack/enterprise-attack.json \\\n"
            "    https://raw.githubusercontent.com/mitre-attack/attack-stix-data/"
            "master/enterprise-attack/enterprise-attack.json"
        )

    objects, version = _read_stix_objects(path)

    tactics = {
        obj["id"]: obj for obj in objects
        if obj.get("type") == "x-mitre-tactic" and _is_active(obj)
    }
    # El orden de las tácticas no es alfabético ni arbitrario: lo define la
    # matriz empresarial, y es lo que da sentido a la prediccion de kill-chain.
    tactic_order: list[str] = []
    for matrix in (o for o in objects if o.get("type") == "x-mitre-matrix"):
        for ref in matrix.get("tactic_refs", []):
            tactic = tactics.get(ref)
            if tactic and tactic["x_mitre_shortname"] not in tactic_order:
                tactic_order.append(tactic["x_mitre_shortname"])

    tactic_names = {t["x_mitre_shortname"]: t["name"] for t in tactics.values()}

    techniques: dict[str, Technique] = {}
    for obj in objects:
        if obj.get("type") != "attack-pattern" or not _is_active(obj):
            continue
        technique_id = _attack_id(obj)
        if not technique_id:
            continue
        is_sub = bool(obj.get("x_mitre_is_subtechnique"))
        techniques[technique_id] = Technique(
            id=technique_id,
            name=obj.get("name", technique_id),
            tactics=[p["phase_name"] for p in obj.get("kill_chain_phases", [])
                     if p.get("kill_chain_name") == "mitre-attack"],
            is_subtechnique=is_sub,
            parent=technique_id.split(".", 1)[0] if is_sub else None,
        )

    return AttackData(
        techniques=techniques,
        tactic_order=tactic_order,
        tactic_names=tactic_names,
        version=version,
        generated_at=datetime.now(tz=timezone.utc).isoformat(timespec="seconds"),
        source="stix",
    )


#: Tipos de objeto STIX que necesita el pipeline. El bundle oficial trae 26 000
#: objetos, de los que el 80% son relaciones que aquí no se usan.
STIX_TYPES = ("attack-pattern", "x-mitre-tactic", "x-mitre-matrix", "x-mitre-collection")


def _read_stix_directly(path: Path) -> tuple[list[dict[str, Any]], str]:
    """Interpreta el bundle como JSON plano, que es lo que es."""
    bundle = json.loads(path.read_text(encoding="utf-8"))
    objects = [o for o in bundle.get("objects", []) if o.get("type") in STIX_TYPES]
    return objects, _stix_version(objects)


def _read_stix_objects(path: Path) -> tuple[list[dict[str, Any]], str]:
    """
    Devuelve los objetos STIX y la versión de ATT&CK del bundle.

    Se prefiere `mitreattack-python`, que valida el STIX y es la vía que
    recomienda MITRE. Pero su validación es estricta: un bundle parcial o
    recortado la hace fallar entera. Como el formato es JSON plano, se cae a
    interpretarlo directamente en vez de dejar al usuario sin matriz.
    """
    try:
        from mitreattack.stix20 import MitreAttackData
    except ImportError:
        logger.info("mitreattack-python no esta instalada; se lee el STIX directamente.")
        return _read_stix_directly(path)

    try:
        data = MitreAttackData(str(path))
        objects: list[dict[str, Any]] = []
        for kind in STIX_TYPES:
            objects.extend(dict(obj) for obj in data.get_objects_by_type(kind))
        return objects, _stix_version(objects)
    except Exception as exc:
        logger.warning(
            "mitreattack-python rechazo el bundle (%s: %s); se interpreta el STIX "
            "directamente.", type(exc).__name__, exc,
        )
        return _read_stix_directly(path)


def _stix_version(objects: list[dict[str, Any]]) -> str:
    """La versión de ATT&CK vive en el objeto `x-mitre-collection`."""
    for obj in objects:
        if obj.get("type") == "x-mitre-collection":
            versions = obj.get("x_mitre_version")
            if versions:
                return str(versions)
    return "desconocida"
