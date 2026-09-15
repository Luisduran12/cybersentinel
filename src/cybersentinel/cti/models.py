"""
Modelos de Dominio de Cyber Threat Intelligence (CTI).

Implementa un subconjunto minimalista inspirado en STIX 2.1 para mantener la
simplicidad y el enfoque académico de CyberSentinel, garantizando que el sistema 
solo almacena los campos que realmente aportan contexto a las detecciones.
"""
from dataclasses import dataclass, field
from typing import Optional
from datetime import datetime

@dataclass
class Indicator:
    """Representa un Indicador de Compromiso (IoC) como IPs o hashes maliciosos."""
    id: str
    pattern: str  # e.g., "[ipv4-addr:value = '198.51.100.1']"
    valid_from: datetime
    valid_until: Optional[datetime] = None
    revoked: bool = False
    name: Optional[str] = None
    description: Optional[str] = None
    labels: list[str] = field(default_factory=list)

@dataclass
class AttackPattern:
    """Técnica o sub-técnica de MITRE ATT&CK (ej. T1059.001)."""
    id: str
    name: str
    description: Optional[str] = None
    kill_chain_phases: list[str] = field(default_factory=list)

@dataclass
class ThreatActor:
    """Agente de amenaza documentado (ej. APT28, Lazarus Group)."""
    id: str
    name: str
    description: Optional[str] = None
    aliases: list[str] = field(default_factory=list)

@dataclass
class ThreatIntelHit:
    """
    Estructura que encapsula el resultado positivo de un cruce entre
    los artefactos observables de un evento y la base de conocimiento CTI.
    """
    observable_value: str
    indicator: Indicator
    related_actors: list[ThreatActor] = field(default_factory=list)
    related_patterns: list[AttackPattern] = field(default_factory=list)
    
    def to_dict(self) -> dict:
        return {
            "observable_value": self.observable_value,
            "indicator_id": self.indicator.id,
            "actors": [a.name for a in self.related_actors],
            "patterns": [p.name for p in self.related_patterns]
        }
