"""
Motor de enriquecimiento CTI (Fase 5).

Recibe eventos o evidencia y los cruza contra el Ingestor de STIX
para encontrar coincidencias (IOC hits).
"""
import re
import logging
from typing import Optional

from cybersentinel.schema import SecurityEvent
from cybersentinel.cti.stix_ingestor import StixIngestor
from cybersentinel.cti.models import ThreatIntelHit

logger = logging.getLogger(__name__)

from datetime import datetime, timezone

class CTIEnricher:
    def __init__(self, ingestor: StixIngestor):
        self.ingestor = ingestor
        
        # Diccionario inverso rápido para matching: valor crudo -> lista de Indicator IDs
        self._lookup: dict[str, list[str]] = {}
        self._build_lookup()

    def _build_lookup(self) -> None:
        """
        Extrae todos los valores crudos (IP, Hash) del patrón STIX para permitir
        búsquedas rápidas. 
        Ejemplo: "[ipv4-addr:value = '198.51.100.1' OR ipv4-addr:value = '10.0.0.1']"
        """
        # Regex heurístico para extraer el contenido entre comillas simples o dobles
        # Usamos finditer para soportar múltiples observables en un mismo patrón (OR/AND).
        pattern_regex = re.compile(r"=\s*['\"]([^'\"]+)['\"]")
        
        for ind_id, ind in self.ingestor.indicators.items():
            for match in pattern_regex.finditer(ind.pattern):
                val = match.group(1).lower()
                if val not in self._lookup:
                    self._lookup[val] = []
                self._lookup[val].append(ind_id)

    def extract_observables(self, event: SecurityEvent) -> list[str]:
        """Extrae strings crudos (IPs, hashes) del evento normalizado."""
        obs = []
        if event.src_ip: obs.append(event.src_ip.lower())
        if event.dst_ip: obs.append(event.dst_ip.lower())
        
        # Extraer hashes de las properties
        hashes = event.properties.get("hashes", {})
        for h_val in hashes.values():
            if isinstance(h_val, str):
                obs.append(h_val.lower())
                
        return obs

    def enrich_event(self, event: SecurityEvent) -> list[ThreatIntelHit]:
        """
        Cruza los observables del evento contra la base CTI.
        Devuelve una lista de aciertos de inteligencia (Hits).
        """
        observables = self.extract_observables(event)
        hits = []
        now = datetime.now(timezone.utc)
        
        for obs in observables:
            if obs in self._lookup:
                for indicator_id in self._lookup[obs]:
                    indicator = self.ingestor.indicators[indicator_id]
                    
                    # Filtros de ciclo de vida (Lifecycle)
                    if indicator.revoked:
                        continue
                    if indicator.valid_until and indicator.valid_until < now:
                        continue
                        
                    actors = self.ingestor.get_related_actors(indicator_id)
                    patterns = self.ingestor.get_related_patterns(indicator_id)
                    
                    hit = ThreatIntelHit(
                        observable_value=obs,
                        indicator=indicator,
                        related_actors=actors,
                        related_patterns=patterns
                    )
                    hits.append(hit)
                
        return hits
