"""임베딩 모듈 — BAAI/bge-small-en-v1.5 싱글톤 래퍼."""

from __future__ import annotations

import threading
from functools import lru_cache

from sentence_transformers import SentenceTransformer

EMBED_MODEL = "BAAI/bge-small-en-v1.5"
BGE_PREFIX = "Represent this sentence for searching relevant passages: "

_lock = threading.Lock()
_model: SentenceTransformer | None = None


def get_embedder() -> SentenceTransformer:
    """프로세스 당 한 번만 로드하는 싱글톤."""
    global _model
    if _model is None:
        with _lock:
            if _model is None:
                _model = SentenceTransformer(EMBED_MODEL)
    return _model


def embed_query(text: str) -> list[float]:
    """쿼리 텍스트를 BGE 벡터로 변환 (384차원, L2 정규화)."""
    model = get_embedder()
    return model.encode(
        BGE_PREFIX + text,
        normalize_embeddings=True,
        convert_to_numpy=True,
    ).tolist()


def embed_documents(texts: list[str]) -> list[list[float]]:
    """문서 배치를 BGE 벡터로 변환."""
    model = get_embedder()
    prefixed = [BGE_PREFIX + t for t in texts]
    vecs = model.encode(prefixed, normalize_embeddings=True, convert_to_numpy=True)
    return vecs.tolist()
