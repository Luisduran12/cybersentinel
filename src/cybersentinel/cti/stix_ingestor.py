"""
Ingestor de STIX 2.1 local (Fase 5).

Se encarga de parsear un STIX Bundle JSON y transformarlo a los objetos
de dominio interno de CTI. Evita dependencias activas externas.
"""
import json
import logging
from pathlib import Path
from datetime import datetime, timezone
from typing import Any

from stix2 import parse
from .models import Indicator, AttackPattern, ThreatActor

logger = logging.getLogger(__name__)

class StixIngestor:
    def __init__(self):
        self.indicators: dict[str, Indicator] = {}
        self.patterns: dict[str, AttackPattern] = {}
        self.actors: dict[str, ThreatActor] = {}
        
        # Mapa de relacionales (indicator_id -> [related_ids])
        self.relationships: dict[str, list[str]] = {}

    def load_from_file(self, filepath: Path) -> None:
        """Carga un Bundle STIX local."""
        try:
            with open(filepath, "r", encoding="utf-8") as f:
                data = json.load(f)
            self.load_bundle(data)
        except Exception as e:
            logger.error(f"Error cargando bundle STIX {filepath}: {e}")
            raise

    def load_bundle(self, bundle_dict: dict[str, Any]) -> None:
        """Parsea un diccionario STIX Bundle en memoria."""
        bundle = parse(bundle_dict, allow_custom=True)
        
        for obj in bundle.objects:
            if obj.type == "indicator":
                self.indicators[obj.id] = Indicator(
                    id=obj.id,
                    pattern=obj.pattern,
                    valid_from=obj.valid_from if hasattr(obj, "valid_from") else datetime.now(timezone.utc),
                    valid_until=getattr(obj, "valid_until", None),
                    revoked=getattr(obj, "revoked", False),
                    name=getattr(obj, "name", None),
                    description=getattr(obj, "description", None),
                    labels=getattr(obj, "labels", [])
                )
            elif obj.type == "attack-pattern":
                self.patterns[obj.id] = AttackPattern(
                    id=obj.id,
                    name=obj.name,
                    description=getattr(obj, "description", None),
                    kill_chain_phases=[kc.phase_name for kc in getattr(obj, "kill_chain_phases", [])]
                )
            elif obj.type == "threat-actor":
                self.actors[obj.id] = ThreatActor(
                    id=obj.id,
                    name=obj.name,
                    description=getattr(obj, "description", None),
                    aliases=getattr(obj, "aliases", [])
                )
            elif obj.type == "relationship":
                src = obj.source_ref
                tgt = obj.target_ref
                if src not in self.relationships:
                    self.relationships[src] = []
                self.relationships[src].append(tgt)

    def get_related_actors(self, indicator_id: str) -> list[ThreatActor]:
        """Recupera los Threat Actors relacionados a un indicador específico."""
        res = []
        if indicator_id in self.relationships:
            for tgt in self.relationships[indicator_id]:
                if tgt in self.actors:
                    res.append(self.actors[tgt])
        return res

    def get_related_patterns(self, indicator_id: str) -> list[AttackPattern]:
        """Recupera los patrones MITRE ATT&CK relacionados a un indicador."""
        res = []
        if indicator_id in self.relationships:
            for tgt in self.relationships[indicator_id]:
                if tgt in self.patterns:
                    res.append(self.patterns[tgt])
        return res
