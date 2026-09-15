"""
Motor de Búsqueda Semántica (RAG) de CyberSentinel (Fase 5).

Se encarga de la ingesta de documentos locales (Markdown, TXT),
su segmentación (Chunking) y el almacenamiento en un Vector Store
para posterior recuperación basada en contexto.
"""
import logging
import hashlib
from pathlib import Path
from typing import Optional

from langchain_core.documents import Document
from langchain_core.embeddings import Embeddings
from langchain_text_splitters import MarkdownTextSplitter
from langchain_community.vectorstores import FAISS

logger = logging.getLogger(__name__)

class RAGStore:
    def __init__(self, embeddings: Embeddings):
        """
        Inicializa el store con un modelo de embeddings inyectado.
        El modelo de embeddings es responsable de transformar texto a vectores.
        """
        self.embeddings = embeddings
        self.vectorstore: Optional[FAISS] = None
        self.splitter = MarkdownTextSplitter(chunk_size=500, chunk_overlap=50)
        self.indexed_hashes: set[str] = set()
        #: Índice léxico por nombre de archivo, para anclar la recuperación en un
        #: identificador exacto cuando se conoce (p. ej. "T1110.md").
        self._by_filename: dict[str, list[Document]] = {}

    def ingest_file(self, filepath: Path) -> None:
        """
        Lee un archivo, lo segmenta asegurando la trazabilidad (provenance)
        y lo indexa en la base vectorial si no ha sido ingestato antes.
        """
        if not filepath.exists():
            logger.warning(f"No se encontro el archivo para RAG: {filepath}")
            return
            
        with open(filepath, "r", encoding="utf-8") as f:
            content = f.read()
            
        # Deduplicación por hash
        file_hash = hashlib.sha256(content.encode("utf-8")).hexdigest()
        if file_hash in self.indexed_hashes:
            logger.warning(f"Documento duplicado saltado: {filepath.name}")
            return
        
        self.indexed_hashes.add(file_hash)
        
        chunks = self.splitter.split_text(content)
        
        # Provenance: Cada chunk debe conservar su origen para citabilidad
        documents = [
            Document(
                page_content=chunk,
                metadata={
                    "source_uri": str(filepath),
                    "filename": filepath.name
                }
            )
            for chunk in chunks
        ]
        
        self.ingest_documents(documents)
        logger.info(f"RAG indexó {len(chunks)} chunks desde {filepath.name}")

    def _documents_from_file(self, filepath: Path) -> list[Document]:
        """Lee y segmenta un archivo, conservando su procedencia en cada fragmento."""
        if not filepath.exists():
            logger.warning(f"No se encontro el archivo para RAG: {filepath}")
            return []

        content = filepath.read_text(encoding="utf-8")

        file_hash = hashlib.sha256(content.encode("utf-8")).hexdigest()
        if file_hash in self.indexed_hashes:
            logger.warning(f"Documento duplicado saltado: {filepath.name}")
            return []
        self.indexed_hashes.add(file_hash)

        return [
            Document(
                page_content=chunk,
                metadata={"source_uri": str(filepath), "filename": filepath.name},
            )
            for chunk in self.splitter.split_text(content)
        ]

    def ingest_directory(self, dirpath: Path, ext: str = "*.md") -> None:
        """
        Ingesta un directorio completo **en una sola pasada**.

        Es importante que sea una sola pasada y no un bucle sobre `ingest_file`:
        un modelo de embeddings que se ajusta sobre el corpus (como el LSA local)
        se ajustaría con el primer archivo y proyectaría los demás en un espacio
        construido a partir de un único documento. El resultado es una
        recuperación esencialmente arbitraria, que es peor que no tener RAG:
        el modelo citaría fuentes que no vienen al caso.
        """
        documents: list[Document] = []
        for filepath in sorted(dirpath.rglob(ext)):
            documents.extend(self._documents_from_file(filepath))

        if not documents:
            logger.warning(f"No se indexo ningun documento desde {dirpath}")
            return

        self.ingest_documents(documents)
        logger.info(f"RAG indexo {len(documents)} fragmentos desde {dirpath}")

    def retrieve_grounded(
        self, query: str, anchors: list[str], k: int = 3
    ) -> list[Document]:
        """
        Recuperación híbrida: anclaje léxico exacto más búsqueda semántica.

        Cuando el sistema ya sabe de qué técnica ATT&CK habla la evidencia, no
        tiene sentido confiar solo en la similitud vectorial para encontrar el
        documento de esa técnica: se busca por identificador exacto y se completa
        con los vecinos semánticos. Así la cita del LLM queda anclada en la
        fuente correcta, que es el requisito para que la explicación sea
        verificable.
        """
        resultado: list[Document] = []
        vistos: set[str] = set()

        for anchor in anchors:
            for doc in self._by_filename.get(f"{anchor}.md", []):
                clave = f"{doc.metadata.get('source_uri')}#{doc.page_content[:60]}"
                if clave not in vistos:
                    vistos.add(clave)
                    resultado.append(doc)
                    break          # un fragmento por ancla basta para citar

        for doc in self.retrieve(query, k=k):
            clave = f"{doc.metadata.get('source_uri')}#{doc.page_content[:60]}"
            if clave not in vistos:
                vistos.add(clave)
                resultado.append(doc)

        return resultado[:k]

    def ingest_documents(self, documents: list[Document]) -> None:
        """Indexa un lote de documentos ya segmentados."""
        if not documents:
            return
        for doc in documents:
            nombre = doc.metadata.get("filename", "")
            if nombre:
                self._by_filename.setdefault(nombre, []).append(doc)
        if self.vectorstore is None:
            self.vectorstore = FAISS.from_documents(documents, self.embeddings)
        else:
            self.vectorstore.add_documents(documents)

    def retrieve(self, query: str, k: int = 3) -> list[Document]:
        """
        Busca los top-K documentos más relevantes para una consulta.
        """
        if not self.vectorstore:
            return []
            
        # Retorna lista de Document (page_content, metadata)
        return self.vectorstore.similarity_search(query, k=k)
