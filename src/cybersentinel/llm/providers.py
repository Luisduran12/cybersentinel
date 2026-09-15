"""
Selección del proveedor de explicación en lenguaje natural.

El pipeline construía un `FakeListChatModel` que devolvía siempre la misma
cadena ("Explicación de prueba del LLM."), y esa cadena llegaba a la salida de la
CLI como si fuera una explicación real. Eso es fabricar evidencia.

Aquí hay exactamente dos caminos, y ambos declaran lo que son:

1. **Claude**, si hay credenciales de Anthropic. Explicación generada por modelo.
   `llm_status = OK`.
2. **Respaldo determinista**, si no las hay o si la API falla. NO es un modelo de
   lenguaje: es una plantilla que redacta con la evidencia disponible, sin
   inventar nada. `llm_status = UNAVAILABLE` o `ERROR`, y `fallback_used = True`.

Nunca hay un tercer camino silencioso. Si el lector de un informe ve una
explicación, puede saber por el estado quién la escribió.
"""
from __future__ import annotations

import logging
import os
from dataclasses import dataclass
from typing import Any

logger = logging.getLogger(__name__)

#: Variable de entorno que habilita el modo con modelo.
API_KEY_ENV = "ANTHROPIC_API_KEY"


@dataclass
class ExplanationResult:
    """Explicación producida, con la procedencia siempre declarada."""

    text: str
    status: str            # OK | UNAVAILABLE | ERROR | DISABLED
    provider: str          # "claude:<modelo>" | "deterministico" | "ninguno"
    fallback_used: bool

    def to_dict(self) -> dict[str, Any]:
        return {
            "text": self.text,
            "status": self.status,
            "provider": self.provider,
            "fallback_used": self.fallback_used,
        }


def anthropic_available() -> bool:
    """¿Hay SDK y credencial para usar el modelo?"""
    if not os.environ.get(API_KEY_ENV):
        return False
    try:
        import anthropic  # noqa: F401
    except ImportError:
        return False
    return True


def build_chat_model(model: str = "claude-opus-5") -> Any | None:
    """
    Construye el cliente de chat de LangChain sobre Anthropic.

    Devuelve None —nunca un doble— si no se puede. Quien llama decide qué hacer
    con esa ausencia, y debe registrarla.
    """
    if not anthropic_available():
        logger.info(
            "Sin credenciales de Anthropic (%s) o sin el paquete 'anthropic': "
            "la explicación usará el respaldo determinista.", API_KEY_ENV,
        )
        return None
    try:
        from langchain_anthropic import ChatAnthropic
    except ImportError:
        logger.info(
            "El paquete 'langchain-anthropic' no está instalado; la explicación "
            "usará el respaldo determinista."
        )
        return None
    try:
        return ChatAnthropic(model=model, max_tokens=800, timeout=30, max_retries=1)
    except Exception as exc:
        logger.warning("No se pudo construir el cliente de Claude: %s", exc)
        return None


def deterministic_explanation(evidence: Any) -> str:
    """
    Redacta la explicación a partir de la evidencia, sin modelo de lenguaje.

    Solo describe lo que hay en la evidencia. Si un componente no aportó nada, lo
    dice; no rellena el hueco con suposiciones.
    """
    partes: list[str] = []

    if evidence.rule_matches:
        reglas = ", ".join(
            f"{h.rule.id} ({h.rule.title})" for h in evidence.rule_matches
        )
        partes.append(f"Reglas de detección activadas: {reglas}.")
    else:
        partes.append("Ninguna regla determinista se activó sobre este evento.")

    if evidence.anomaly_score >= 0.5:
        partes.append(
            f"El detector de anomalías puntúa {evidence.anomaly_score:.3f} sobre una "
            "frontera de 0.500, es decir, el evento se desvía de la línea base "
            "aprendida."
        )
    else:
        partes.append(
            f"El detector de anomalías puntúa {evidence.anomaly_score:.3f}, por debajo "
            "de la frontera de decisión: no lo considera anómalo."
        )

    if evidence.mitre_context:
        tecnicas = ", ".join(evidence.mitre_context)
        tacticas = ", ".join(evidence.mitre_tactics) or "sin táctica resuelta"
        partes.append(f"Técnicas MITRE ATT&CK asociadas: {tecnicas} (tácticas: {tacticas}).")
    else:
        partes.append("No hay técnica ATT&CK asociada a este evento.")

    if evidence.temporal_context:
        partes.append(
            "Correlación temporal: " + "; ".join(evidence.temporal_context) + "."
        )

    if evidence.cti_hits:
        indicadores = ", ".join(
            getattr(h.indicator, "value", "?") for h in evidence.cti_hits
        )
        partes.append(f"Coincidencias de inteligencia de amenazas: {indicadores}.")
    else:
        partes.append("Sin coincidencias en la inteligencia de amenazas cargada (CTI_MATCH=NONE).")

    if evidence.rag_context:
        fuentes = ", ".join(sorted({c.source_uri for c in evidence.rag_context}))
        partes.append(f"Contexto documental recuperado de: {fuentes}.")
    else:
        partes.append("No se recuperó contexto documental relevante.")

    partes.append(
        f"Puntuación híbrida resultante: {evidence.hybrid_score:.1f}/100 "
        f"(estado: {evidence.detection_status})."
    )
    partes.append(
        "Explicación generada de forma determinista a partir de la evidencia: "
        "no intervino ningún modelo de lenguaje."
    )
    return " ".join(partes)
