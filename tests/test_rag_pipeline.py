"""
Tests para el Pipeline RAG (Fase 5).
"""
import pytest
from pathlib import Path
from langchain_core.embeddings import FakeEmbeddings
from cybersentinel.rag.vector_store import RAGStore

def test_rag_ingest_and_retrieve(tmp_path: Path):
    # 1. Crear documento de prueba (CTI Report Mock)
    doc_path = tmp_path / "report.md"
    content = (
        "# Reporte CTI 2026\n\n"
        "El grupo APT28 ha estado utilizando la IP maliciosa 198.51.100.99 "
        "en ataques recientes contra infraestructuras críticas. "
        "Utilizan la técnica T1059.001 para ejecución de scripts."
    )
    doc_path.write_text(content, encoding="utf-8")
    
    # 2. Configurar RAG con FakeEmbeddings (dimension=10 para tests rápidos)
    # FakeEmbeddings genera vectores aleatorios y responde a similarity_search.
    embeddings = FakeEmbeddings(size=10)
    store = RAGStore(embeddings)
    
    # 3. Ingestar
    store.ingest_file(doc_path)
    
    # 4. Recuperar (Aunque sean fake embeddings, el FAISS funcionará y 
    # la similitud devolverá el chunk disponible).
    results = store.retrieve("IP maliciosa APT28", k=1)
    
    assert len(results) == 1
    chunk = results[0]
    
    # Verificar Provenance
    assert chunk.metadata["filename"] == "report.md"
    assert "source_uri" in chunk.metadata
    
    # Verificar Contenido
    assert "198.51.100.99" in chunk.page_content
    assert "T1059.001" in chunk.page_content
