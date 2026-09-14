"""
Explicabilidad (XAI): convierte un incidente técnico en una narrativa legible.

El agente redacta, por cada incidente: qué vio, por qué es sospechoso, el nivel
de confianza, la evidencia citada y la predicción de la fase siguiente.

Dos modos:
  - LOCAL (por defecto): plantilla determinista, sin dependencias externas ni
    costos. Siempre funciona, ideal para reproducibilidad en la tesis.
  - LLM (opcional): si hay una API key de Anthropic, enriquece la narrativa con
    Claude. Se activa explícitamente; nunca es obligatorio.

Separar ambos modos permite defender ante el jurado que el sistema funciona de
forma verificable aun sin depender de un modelo externo.
"""
from __future__ import annotations

import os
from dataclasses import dataclass
from typing import Any

from ..correlation.correlator import Incident
from ..correlation import mitre


@dataclass
class IncidentNarrative:
    incident_id: str
    summary: str
    reasoning: str
    evidence: list[str]
    prediction_text: str
    confidence: float

    def to_dict(self) -> dict[str, Any]:
        return {
            "incident_id": self.incident_id,
            "summary": self.summary,
            "reasoning": self.reasoning,
            "evidence": self.evidence,
            "prediction_text": self.prediction_text,
            "confidence": round(self.confidence, 3),
        }

    def to_text(self) -> str:
        lines = [
            f"== {self.incident_id} ==",
            f"Resumen: {self.summary}",
            f"Razonamiento: {self.reasoning}",
            "Evidencia:",
        ]
        lines += [f"  - {e}" for e in self.evidence]
        lines.append(f"Predicción: {self.prediction_text}")
        lines.append(f"Confianza global: {self.confidence:.0%}")
        return "\n".join(lines)


class Explainer:
    """Genera narrativas explicables de incidentes."""

    def __init__(self, use_llm: bool = False, model: str = "claude-sonnet-4-6") -> None:
        self.use_llm = use_llm
        self.model = model

    def explain(self, incident: Incident) -> IncidentNarrative:
        base = self._explain_local(incident)
        if self.use_llm and os.environ.get("ANTHROPIC_API_KEY"):
            enriched = self._enrich_with_llm(incident, base)
            if enriched:
                return enriched
        return base

    # --- Modo local (determinista) -------------------------------------------
    def _explain_local(self, incident: Incident) -> IncidentNarrative:
        techs = incident.techniques
        tech_str = ", ".join(f"{t} ({mitre.technique_name(t)})" for t in techs) or "sin técnica ATT&CK específica"
        sev = incident.max_severity.value
        risk = incident.risk_score

        summary = (
            f"Incidente sobre la entidad '{incident.entity}' con {len(incident.findings)} "
            f"hallazgo(s), severidad máxima {sev} y riesgo agregado {risk}/100."
        )

        reasoning_parts = [
            f"Se correlacionaron {len(incident.findings)} hallazgos en la ventana "
            f"{incident.start:%Y-%m-%d %H:%M} – {incident.end:%H:%M} UTC.",
            f"Técnicas MITRE ATT&CK involucradas: {tech_str}.",
        ]
        if incident.tactics:
            chain = " → ".join(mitre.TACTIC_LABELS_ES.get(t, t) for t in incident.tactics)
            reasoning_parts.append(f"Progresión táctica observada: {chain}.")
        reasoning = " ".join(reasoning_parts)

        evidence: list[str] = []
        for f in sorted(incident.findings, key=lambda x: x.event.timestamp):
            ts = f.event.timestamp.strftime("%H:%M:%S")
            src = f.event.source
            ev = f"[{ts}] ({src}) {f.title} — conf. {f.confidence:.0%}"
            if f.event.command_line:
                cmd = f.event.command_line[:120]
                ev += f" | cmd: {cmd}"
            elif f.event.src_ip:
                ev += f" | src_ip: {f.event.src_ip}"
            evidence.append(ev)

        if incident.prediction:
            prediction_text = incident.prediction.rationale
            confidence = incident.prediction.confidence
        else:
            prediction_text = "No hay suficiente progresión para predecir una fase siguiente con fiabilidad."
            confidence = 0.4

        # Confianza global = mezcla de confianza de hallazgos y de la predicción.
        finding_conf = sum(f.confidence for f in incident.findings) / max(len(incident.findings), 1)
        global_conf = round(0.6 * finding_conf + 0.4 * confidence, 3)

        return IncidentNarrative(
            incident_id=incident.incident_id,
            summary=summary,
            reasoning=reasoning,
            evidence=evidence,
            prediction_text=prediction_text,
            confidence=global_conf,
        )

    # --- Modo LLM (opcional) --------------------------------------------------
    def _enrich_with_llm(self, incident: Incident, base: IncidentNarrative) -> IncidentNarrative | None:
        """Enriquece la narrativa usando la API de Anthropic, si está disponible."""
        try:
            import anthropic
        except ImportError:
            return None
        try:
            client = anthropic.Anthropic()
            prompt = (
                "Eres un analista SOC senior. Redacta un resumen ejecutivo claro y "
                "conciso (máx. 6 líneas) de este incidente para un reporte. No inventes "
                "datos; usa solo lo provisto.\n\n"
                f"Datos del incidente:\n{incident.to_dict()}\n\n"
                f"Evidencia:\n{base.evidence}\n"
            )
            resp = client.messages.create(
                model=self.model,
                max_tokens=500,
                messages=[{"role": "user", "content": prompt}],
            )
            text = "".join(block.text for block in resp.content if getattr(block, "type", "") == "text")
            if text.strip():
                base.summary = text.strip()
            return base
        except Exception:
            # Cualquier fallo del LLM => se mantiene la narrativa local (fail-safe).
            return None
