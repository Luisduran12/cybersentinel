"""
Módulo de Detección Híbrida (Fase 4).

Define las interfaces para unificar la evidencia proveniente de las reglas
deterministas (Sigma) con el Machine Learning (Isolation Forest) y el contexto
temporal (secuencias ATT&CK).
"""
from __future__ import annotations
from dataclasses import dataclass, field
from datetime import datetime, timezone
from typing import Any

from .rules_engine import RuleHit
from .temporal import CorrelatedIncident
from cybersentinel.cti.models import ThreatIntelHit

#: Valor explícito para "este componente no aportó información".
#: Se prefiere a un campo vacío ambiguo: distingue "no había nada" de "no se
#: ejecutó", que son situaciones distintas para el analista.
NOT_AVAILABLE = "not_available"


@dataclass
class RetrievedContext:
    """
    Un fragmento recuperado por RAG, con su procedencia.

    Sin `source_uri` la cita del LLM no es verificable, y una explicación que no
    se puede verificar no es evidencia.
    """

    source_uri: str
    excerpt: str
    filename: str = ""

    def to_dict(self) -> dict[str, Any]:
        return {
            "source_uri": self.source_uri,
            "filename": self.filename,
            "excerpt": self.excerpt[:400],
        }

@dataclass
class DetectionEvidence:
    """
    Agrupa todas las señales relacionadas con un evento o cadena de eventos
    para formar un veredicto híbrido.
    """
    event_id: str
    rule_matches: list[RuleHit] = field(default_factory=list)
    anomaly_score: float = 0.0
    temporal_context: list[str] = field(default_factory=list)
    mitre_context: list[str] = field(default_factory=list)
    cti_hits: list[ThreatIntelHit] = field(default_factory=list)

    # --- Trazabilidad ---
    #: Ejecución a la que pertenece esta evidencia.
    run_id: str = ""
    #: Huella estable del evento original (event_id puede repetirse).
    event_ref: str = ""
    #: Momento en que se construyó la evidencia.
    created_at: str = field(
        default_factory=lambda: datetime.now(tz=timezone.utc).isoformat(timespec="milliseconds")
    )

    # --- Contexto ATT&CK observado (no cobertura estructural) ---
    #: Tácticas de las técnicas efectivamente disparadas por las reglas.
    mitre_tactics: list[str] = field(default_factory=list)

    # --- Contexto recuperado y explicación ---
    rag_context: list[RetrievedContext] = field(default_factory=list)
    explanation: str = ""
    #: Estado del LLM: OK, UNAVAILABLE, ERROR o DISABLED.
    llm_status: str = "DISABLED"
    #: True si la explicación la produjo el respaldo determinista, no el modelo.
    fallback_used: bool = False
    #: Estado de cada etapa, copiado de la traza para que la evidencia sea
    #: autocontenida al exportarse.
    stage_status: dict[str, str] = field(default_factory=dict)

    #: Entidad afectada (host, usuario o IP). La necesita la capa de gobernanza
    #: para saber sobre qué se propone actuar.
    entity: str = ""

    @property
    def tactics(self) -> list[str]:
        """Alias de mitre_tactics para la capa de respuesta."""
        return self.mitre_tactics

    @property
    def has_cti(self) -> bool:
        return bool(self.cti_hits)

    @property
    def has_rag(self) -> bool:
        return bool(self.rag_context)

    @property
    def detection_status(self) -> str:
        """
        Resumen de por qué (o por qué no) esto es una detección.

        Distingue las tres situaciones que el analista necesita separar: lo
        detectó una regla determinista, lo señaló solo el modelo, o no lo vio
        nadie.
        """
        if self.rule_matches and self.anomaly_score >= 0.5:
            return "RULE_AND_ANOMALY"
        if self.rule_matches:
            return "RULE_MATCH"
        if self.anomaly_score >= 0.5:
            return "ANOMALY_ONLY"
        return "NO_DETECTION"
    
    @property
    def hybrid_score(self) -> float:
        """
        Calcula un score de riesgo compuesto.
        Fase 4: Fórmula heurística simple, que podrá ser reemplazada por ML en Fase 5+.
        """
        base = 0.0
        # 1. Las reglas deterministas aportan fuerte confianza
        if self.rule_matches:
            base += 50.0
        
        # 2. El ML modula el riesgo basado en cuán raro es
        # anomaly_score está en [0, 1]. Si es mayor a 0.5 es anómalo.
        ml_boost = max(0, (self.anomaly_score - 0.5) * 40.0)
        base += ml_boost
        
        # 3. Contexto temporal (ej. secuencias previas) aporta confianza extra
        if self.temporal_context:
            base += 30.0
            
        # 4. Evidencia CTI aporta confianza determinista adicional basada en severidad
        for hit in self.cti_hits:
            labels = set(hit.indicator.labels)
            actors = {a.name.lower() for a in hit.related_actors}
            
            # CTI Crítico (Actores de estado, C2, etc)
            if "nation-state" in labels or "c2" in labels or "apt28" in actors:
                base += 50.0
            # CTI Alto (Malware general)
            elif "malicious" in labels or "malware" in labels:
                base += 30.0
            # CTI Medio (Anomalous)
            elif "anomalous-activity" in labels:
                base += 15.0
            # CTI Bajo (Benigno pero vigilado, spam, etc)
            elif "benign_but_watched" in labels or "spam" in labels:
                base += 5.0
            else:
                # Fallback por defecto si tiene labels no mapeados pero es un match
                base += 10.0
            
        return min(100.0, base)

    @property
    def techniques(self) -> list[str]:
        """Alias de mitre_context para compatibilidad con navigator.layer_from_incidents."""
        return self.mitre_context

    @property
    def risk_score(self) -> float:
        """Alias de hybrid_score para compatibilidad con navigator.layer_from_incidents."""
        return self.hybrid_score

    @property
    def incident_id(self) -> str:
        """Alias de event_id para compatibilidad con navigator.layer_from_incidents."""
        return self.event_id

    def to_dict(self) -> dict[str, Any]:
        return {
            "run_id": self.run_id or NOT_AVAILABLE,
            "event_id": self.event_id,
            "event_ref": self.event_ref or NOT_AVAILABLE,
            "created_at": self.created_at,
            "detection_status": self.detection_status,
            "rule_matches": [r.rule.id for r in self.rule_matches],
            "rule_titles": [r.rule.title for r in self.rule_matches],
            "anomaly_score": round(self.anomaly_score, 4),
            "temporal_context": self.temporal_context,
            "mitre_context": self.mitre_context or NOT_AVAILABLE,
            "mitre_tactics": self.mitre_tactics or NOT_AVAILABLE,
            "cti_hits": [hit.to_dict() for hit in self.cti_hits] or NOT_AVAILABLE,
            "rag_context": [c.to_dict() for c in self.rag_context] or NOT_AVAILABLE,
            "explanation": self.explanation or NOT_AVAILABLE,
            "llm_status": self.llm_status,
            "fallback_used": self.fallback_used,
            "stage_status": self.stage_status,
            "entity": self.entity or NOT_AVAILABLE,
            "hybrid_score": round(self.hybrid_score, 2),
        }
