"""
Tests para el motor de LLM Explainer (Fase 5).
"""
import pytest
from langchain_core.messages import BaseMessage, AIMessage
from langchain_core.language_models.chat_models import BaseChatModel
from langchain_core.documents import Document

from cybersentinel.detection.hybrid import DetectionEvidence
from cybersentinel.llm.explainer import LLMExplainer, SYSTEM_PROMPT

from typing import Any

class MockChatModel(BaseChatModel):
    """Un chat model falso para probar los prompts sin llamadas a API."""
    last_messages: list[Any] = []
    
    @property
    def _llm_type(self) -> str:
        return "mock-chat-model"

    def _generate(self, messages, stop=None, run_manager=None, **kwargs):
        from langchain_core.outputs import ChatResult, ChatGeneration
        
        # Guardar el input para aserciones
        self.last_messages = messages
        
        # Simular una respuesta obediente que cita la fuente
        response = "El ataque detectado corresponde a T1059.001 [file:///docs/t1059.md]."
        return ChatResult(generations=[ChatGeneration(message=AIMessage(content=response))])

def test_llm_explainer_passes_correct_context():
    mock_llm = MockChatModel()
    explainer = LLMExplainer(mock_llm)
    
    evidence = DetectionEvidence(
        event_id="ev_test",
        anomaly_score=0.9
    )
    
    docs = [
        Document(
            page_content="T1059.001 es Command and Scripting Interpreter: PowerShell.",
            metadata={"source_uri": "file:///docs/t1059.md"}
        )
    ]
    
    result = explainer.generate_explanation(evidence, docs)
    
    # Verificar que el LLM retornó la respuesta
    assert "T1059.001" in result
    assert "[file:///docs/t1059.md]" in result
    
    # Verificar que el System Prompt defensivo fue inyectado
    system_msg = mock_llm.last_messages[0]
    human_msg = mock_llm.last_messages[1]
    
    assert system_msg.content == SYSTEM_PROMPT
    # Verificar que el contexto y la evidencia se pasaron
    assert "file:///docs/t1059.md" in human_msg.content
    assert "ev_test" in human_msg.content
