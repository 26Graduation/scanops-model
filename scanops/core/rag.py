"""RAG 파이프라인 — Qdrant 검색 + Ollama LLM 응답."""

from __future__ import annotations

import json
import os
from typing import Iterator

import requests
from qdrant_client import QdrantClient
from qdrant_client.models import FieldCondition, Filter, MatchValue

from .embedder import embed_query

QDRANT_URL = os.getenv("QDRANT_URL", "http://localhost:6333")
# QDRANT_PATH: 설정 시 Docker 없이 embedded 모드 (로컬 개발 fallback)
QDRANT_PATH = os.getenv("QDRANT_PATH", "")
COLLECTION_NAME = os.getenv("QDRANT_COLLECTION", "cve_vulnerabilities")
OLLAMA_URL = os.getenv("OLLAMA_URL", "http://localhost:11434/api/generate")
LLM_MODEL = os.getenv("OLLAMA_MODEL", "qwen2.5-coder:1.5b")

SYSTEM_PERSONA = """\
You are a senior security engineer with deep CVE/CWE expertise.
When analyzing code or a vulnerability query, always output AT LEAST 3 findings in this format:

1. Vulnerability name
2. CVE ID (if a matching CVE exists in the provided context)
3. CWE ID
4. CVSS score and severity level
5. Vulnerable location (file/line if known)
6. Fix with code snippet

Prioritize CRITICAL and HIGH findings. Answer in the same language as the question."""

_qdrant_client: QdrantClient | None = None


def _get_client() -> QdrantClient:
    """
    Qdrant 클라이언트 싱글톤.
    - 기본: URL 서버 모드 (Docker localhost:6333 또는 Railway)
    - QDRANT_PATH 환경변수 설정 시에만 embedded 로컬 모드 사용
    """
    global _qdrant_client
    if _qdrant_client is None:
        if QDRANT_PATH:
            os.makedirs(QDRANT_PATH, exist_ok=True)
            _qdrant_client = QdrantClient(path=QDRANT_PATH)
        else:
            _qdrant_client = QdrantClient(url=QDRANT_URL)
    return _qdrant_client


def search_cves(
    query: str,
    top_k: int = 5,
    severity_filter: str | None = None,
) -> list[dict]:
    """쿼리 텍스트와 유사한 CVE를 Qdrant에서 검색한다."""
    vec = embed_query(query)
    q_filter = None
    if severity_filter:
        q_filter = Filter(
            must=[FieldCondition(key="severity", match=MatchValue(value=severity_filter.upper()))]
        )
    results = _get_client().query_points(
        collection_name=COLLECTION_NAME,
        query=vec,
        query_filter=q_filter,
        limit=top_k,
        with_payload=True,
    ).points
    return [
        {
            "score": r.score,
            "cve_id": r.payload.get("cve_id"),
            "severity": r.payload.get("severity"),
            "base_score": r.payload.get("base_score"),
            "attack_vector": r.payload.get("attack_vector"),
            "cwe_id": r.payload.get("cwe_id"),
            "affected_products": r.payload.get("affected_products", []),
            "cvss_vector": r.payload.get("cvss_vector"),
            "description": r.payload.get("description", ""),
        }
        for r in results
    ]


def build_prompt(query: str, cves: list[dict]) -> str:
    """검색된 CVE 컨텍스트와 질문을 합쳐 LLM 프롬프트를 조립한다."""
    blocks = []
    for i, c in enumerate(cves, 1):
        products = ", ".join(c["affected_products"]) or "N/A"
        blocks.append(
            f"[CVE #{i}]\n"
            f"  ID: {c['cve_id']} | Severity: {c['severity']} (CVSS {c['base_score']})\n"
            f"  Attack Vector: {c['attack_vector']} | CWE: {c['cwe_id']}\n"
            f"  Products: {products}\n"
            f"  Description: {c['description']}"
        )
    context = "\n\n".join(blocks) if blocks else "No CVE context available."
    return (
        f"### SYSTEM\n{SYSTEM_PERSONA}\n\n"
        f"### RETRIEVED CVE DATA\n{context}\n\n"
        f"### USER QUESTION\n{query}\n\n"
        f"### RESPONSE"
    )


def stream_llm(prompt: str, model: str = LLM_MODEL) -> Iterator[str]:
    """Ollama 스트리밍 응답을 토큰 단위로 yield한다."""
    payload = {
        "model": model,
        "prompt": prompt,
        "stream": True,
        "options": {"temperature": 0.2, "top_p": 0.9, "num_predict": 1024},
    }
    resp = requests.post(OLLAMA_URL, json=payload, stream=True, timeout=120)
    resp.raise_for_status()
    for line in resp.iter_lines():
        if line:
            chunk = json.loads(line)
            token = chunk.get("response", "")
            if token:
                yield token
            if chunk.get("done"):
                break


_FINETUNED_MODEL_PREFIXES = ("qwen2.5-coder-security", "gemma2-security")

_STOP_TOKENS_BASE = ["<|im_end|>", "<|endoftext|>"]
_STOP_TOKENS_FINETUNED = [
    "<|im_end|>", "<|endoftext|>",
    "[EMPTY_151643]", "[EMPTY_151644]", "[EMPTY_151645]",
    "Human resources", "The following", "\n\n\n",
]


def call_llm(prompt: str, model: str = LLM_MODEL) -> str:
    """LLM 응답 전체 문자열 반환 (스트리밍 없음)."""
    is_finetuned = any(model.startswith(p) for p in _FINETUNED_MODEL_PREFIXES)
    stop_tokens = _STOP_TOKENS_FINETUNED if is_finetuned else _STOP_TOKENS_BASE
    num_predict = 300 if is_finetuned else 1024
    payload = {
        "model": model,
        "prompt": prompt,
        "stream": False,
        "options": {
            "temperature": 0.1 if is_finetuned else 0.2,
            "top_p": 0.8 if is_finetuned else 0.9,
            "num_predict": num_predict,
            "stop": stop_tokens,
            "repeat_penalty": 1.3 if is_finetuned else 1.1,
        },
    }
    resp = requests.post(OLLAMA_URL, json=payload, timeout=120)
    resp.raise_for_status()
    raw = resp.json().get("response", "")
    if is_finetuned:
        # EOS 토큰이 텍스트로 노출된 경우 이후 내용 제거
        for sentinel in ("[EMPTY_", "Human resources", "The following"):
            idx = raw.find(sentinel)
            if idx != -1:
                raw = raw[:idx]
    return raw


def run_rag(
    query: str,
    top_k: int = 5,
    severity_filter: str | None = None,
    stream: bool = True,
    model: str = LLM_MODEL,
) -> tuple[list[dict], str]:
    """
    RAG 전체 파이프라인 실행.

    Returns:
        (cves, answer) — 검색된 CVE 목록과 LLM 응답
    """
    cves = search_cves(query, top_k=top_k, severity_filter=severity_filter)
    prompt = build_prompt(query, cves)
    if stream:
        answer = "".join(stream_llm(prompt, model=model))
    else:
        answer = call_llm(prompt, model=model)
    return cves, answer
