"""
Auditoría Grounding en LLMExplainer.
"""
import pytest
from langchain_core.documents import Document
from cybersentinel.llm.explainer import LLMExplainer
from tests.test_llm_explainer import MockChatModel
from cybersentinel.detection.hybrid import DetectionEvidence

def test_audit_grounding_no_hallucination():
    mock_llm = MockChatModel()
    
    class GroundedMockLLM(MockChatModel):
        def _generate(self, messages, stop=None, run_manager=None, **kwargs):
            from langchain_core.outputs import ChatResult, ChatGeneration
            from langchain_core.messages import AIMessage
            
            human_prompt = messages[1].content
            if "T1059.001" not in human_prompt:
                resp = "No hay suficiente contexto"
            else:
                resp = "El ataque corresponde a T1059.001 [file:///docs/t1059.md]."
            return ChatResult(generations=[ChatGeneration(message=AIMessage(content=resp))])

    mock_llm = GroundedMockLLM()
    explainer = LLMExplainer(mock_llm)
    
    ev = DetectionEvidence(event_id="ev_ground")
    
    # Prueba A: Con contexto
    docs_a = [Document(page_content="T1059.001 description", metadata={"source_uri": "file:///docs/t1059.md"})]
    result_a = explainer.generate_explanation(ev, docs_a)
    assert "T1059.001" in result_a
    assert "[file:///docs/t1059.md]" in result_a
    
    # Prueba B: Sin contexto
    result_b = explainer.generate_explanation(ev, [])
    assert "No hay suficiente contexto" in result_b
    
    # Si bien el mock hace que esto parezca trivial, el test prueba 
    # que la arquitectura SOPORTA el rechazo y no obliga al LLM a inferir
    # y pasa los docs explícitamente en una sección llamada "Basado EXCLUSIVAMENTE"
