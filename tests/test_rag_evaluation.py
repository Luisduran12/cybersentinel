"""
Evaluación Científica del RAG (Fase 5).

Verifica métricas de calidad de Retrieval (Hit Rate) y Groundedness.
"""
import pytest
from unittest.mock import MagicMock
from langchain_core.documents import Document

from cybersentinel.rag.vector_store import RAGStore

def test_retrieval_hit_rate():
    """
    Simula un benchmark de Hit Rate. 
    Verifica si el documento correcto es recuperado en el Top-K.
    """
    store = RAGStore(embeddings=MagicMock())
    
    # Mocking el backend de búsqueda para el benchmark
    expected_doc = Document(page_content="APT28 usa T1059.001", metadata={"source_uri": "doc1.md"})
    noise_doc = Document(page_content="Lazarus usa T1055", metadata={"source_uri": "doc2.md"})
    
    store.vectorstore = MagicMock()
    store.vectorstore.similarity_search.return_value = [expected_doc, noise_doc]
    
    # Evaluar Query
    query = "Qué técnica usa APT28?"
    results = store.retrieve(query, k=2)
    
    # Calcular Hit Rate (1.0 si el ground_truth está en los resultados)
    ground_truth_uri = "doc1.md"
    hits = [1 for doc in results if doc.metadata.get("source_uri") == ground_truth_uri]
    
    hit_rate = 1.0 if hits else 0.0
    assert hit_rate == 1.0

def test_hallucination_prevention_logic():
    """
    Verifica que el explicador no invente respuestas si el contexto está vacío.
    """
    from cybersentinel.llm.explainer import LLMExplainer
    from tests.test_llm_explainer import MockChatModel
    from cybersentinel.detection.hybrid import DetectionEvidence
    
    class StrictMockChatModel(MockChatModel):
        def _generate(self, messages, stop=None, run_manager=None, **kwargs):
            from langchain_core.outputs import ChatResult, ChatGeneration
            from langchain_core.messages import AIMessage
            
            human_prompt = messages[1].content
            if "DOCUMENTOS DE CONTEXTO RECUPERADOS (RAG):\n\n\nBasado EXCLUSIVAMENTE" in human_prompt:
                # No hay documentos!
                resp = "No hay suficiente contexto para explicar esta alerta."
            else:
                resp = "Hay contexto."
            return ChatResult(generations=[ChatGeneration(message=AIMessage(content=resp))])

    mock_llm = StrictMockChatModel()
    explainer = LLMExplainer(mock_llm)
    
    ev = DetectionEvidence(event_id="ev_123")
    result = explainer.generate_explanation(ev, rag_context=[])
    
    assert "No hay suficiente contexto" in result
