"""
Modelo de embeddings local y determinista para el RAG.

Por qué no un modelo neuronal por defecto
-----------------------------------------
El pipeline usaba `FakeEmbeddings`, que devuelve **vectores aleatorios**: la
recuperación resultante no tiene ningún significado semántico. Eso no puede estar
en producción.

La alternativa obvia —`sentence-transformers`— exige descargar un modelo de casi
100 MB desde internet en el primer uso, lo que rompe la reproducibilidad y
convierte una ejecución del agente en una operación con dependencia de red.

Aquí se implementa **LSA** (Latent Semantic Analysis): TF-IDF sobre el corpus
seguido de una descomposición en valores singulares truncada. Es una técnica de
embeddings semánticos clásica y legítima, no un sustituto de mentira:

- captura co-ocurrencia de términos, así que "PowerShell codificado" recupera
  documentos sobre ofuscación aunque no compartan todas las palabras;
- es **determinista** con semilla fija, requisito para que un experimento de
  tesis sea reproducible;
- se entrena sobre el propio corpus, sin red ni descargas.

Su límite hay que declararlo: LSA no entiende sinónimos que nunca coocurren en el
corpus, y un modelo neuronal recuperaría mejor. Por eso la interfaz acepta
cualquier `Embeddings` de LangChain: quien quiera calidad puede inyectar
`sentence-transformers` sin tocar el resto del sistema.
"""
from __future__ import annotations

import logging
from typing import Any

import numpy as np
from langchain_core.embeddings import Embeddings

logger = logging.getLogger(__name__)


class LocalLSAEmbeddings(Embeddings):
    """
    Embeddings semánticos locales por análisis semántico latente.

    Se ajusta la primera vez que recibe documentos. Las consultas posteriores se
    proyectan en el mismo espacio, de modo que consulta y documentos son
    comparables.
    """

    def __init__(self, dimensions: int = 128, random_state: int = 42) -> None:
        self.dimensions = dimensions
        self.random_state = random_state
        self._vectorizer: Any = None
        self._svd: Any = None
        self._fitted = False

    @property
    def is_fitted(self) -> bool:
        return self._fitted

    @property
    def name(self) -> str:
        return f"local-lsa-{self.dimensions}d"

    def _build(self) -> tuple[Any, Any]:
        from sklearn.decomposition import TruncatedSVD
        from sklearn.feature_extraction.text import TfidfVectorizer

        vectorizer = TfidfVectorizer(
            lowercase=True,
            # Los identificadores técnicos (T1059.001, powershell.exe, -enc) son
            # justo lo que hay que conservar en un corpus de ciberseguridad.
            token_pattern=r"(?u)\b[\w.\-]{2,}\b",
            max_features=20000,
            sublinear_tf=True,
        )
        svd = TruncatedSVD(n_components=self.dimensions, random_state=self.random_state)
        return vectorizer, svd

    def fit(self, texts: list[str]) -> "LocalLSAEmbeddings":
        """Ajusta el espacio semántico sobre el corpus completo."""
        if not texts:
            raise ValueError("No se puede ajustar el espacio semántico con un corpus vacío.")

        self._vectorizer, self._svd = self._build()
        matrix = self._vectorizer.fit_transform(texts)

        # SVD no puede extraer más componentes que rango tiene la matriz. Con un
        # corpus pequeño se reduce la dimensión en vez de fallar.
        max_components = max(1, min(self.dimensions, min(matrix.shape) - 1))
        if max_components != self._svd.n_components:
            logger.info(
                "Corpus pequeño (%d documentos): se reduce la dimensión de %d a %d.",
                len(texts), self._svd.n_components, max_components,
            )
            self._svd.n_components = max_components

        self._svd.fit(matrix)
        self._fitted = True
        return self

    def _project(self, texts: list[str]) -> np.ndarray:
        matrix = self._vectorizer.transform(texts)
        vectors = self._svd.transform(matrix)
        # Se normaliza para que el producto interno de FAISS equivalga a la
        # similitud del coseno.
        norms = np.linalg.norm(vectors, axis=1, keepdims=True)
        return vectors / np.where(norms == 0, 1.0, norms)

    def embed_documents(self, texts: list[str]) -> list[list[float]]:
        """
        Vectoriza documentos, ajustando el espacio la primera vez.

        Los documentos añadidos más tarde se proyectan en el espacio ya
        existente: reajustarlo invalidaría los vectores ya indexados en FAISS.
        """
        if not texts:
            return []
        if not self._fitted:
            self.fit(texts)
        return self._project(texts).tolist()

    def embed_query(self, text: str) -> list[float]:
        """Vectoriza una consulta en el mismo espacio que los documentos."""
        if not self._fitted:
            raise RuntimeError(
                "El espacio semántico no está ajustado: hay que indexar documentos "
                "antes de consultar."
            )
        return self._project([text])[0].tolist()
