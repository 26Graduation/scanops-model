"""
RAG Pipeline for ScanOps — Step 6
ChromaDB(792 CVE) → 유사 CVE 검색 → Grok API 컨텍스트 주입 → 취약점 분석

흐름:
    코드 입력
      ↓
    BGE-small 임베딩 → ChromaDB 유사 CVE 검색 (top-5)
      ↓
    "Relevant CVEs: {context}\n\nAnalyze this code: {code}\n\nVULN_TYPE:"
      ↓
    Grok API 응답
"""

import sys
from pathlib import Path

import chromadb
from sentence_transformers import SentenceTransformer

sys.path.insert(0, str(Path(__file__).resolve().parent))
from grok_client import SECURITY_SYSTEM_PROMPT, DEFAULT_MODEL, query_llm

BASE_DIR    = Path(__file__).resolve().parent.parent
CHROMA_DIR  = BASE_DIR / "chroma_db"
COLLECTION  = "cve_collection"
MODEL_NAME  = "BAAI/bge-small-en-v1.5"
BGE_PREFIX  = "Represent this sentence for searching relevant passages: "

# 모듈 수준 싱글톤 — 반복 로드 방지
_chroma_col  = None
_embed_model = None


def _get_resources():
    global _chroma_col, _embed_model
    if _chroma_col is None:
        client      = chromadb.PersistentClient(path=str(CHROMA_DIR))
        _chroma_col = client.get_collection(COLLECTION)
    if _embed_model is None:
        _embed_model = SentenceTransformer(MODEL_NAME)
    return _chroma_col, _embed_model


def search_cve(query: str, n_results: int = 5) -> list[dict]:
    """코드/취약점 설명 쿼리로 ChromaDB에서 유사 CVE를 검색한다."""
    col, model = _get_resources()
    vec = model.encode(BGE_PREFIX + query, normalize_embeddings=True).tolist()
    raw = col.query(
        query_embeddings=[vec],
        n_results=n_results,
        include=["documents", "metadatas", "distances"],
    )
    results = []
    for cve_id, doc, meta, dist in zip(
        raw["ids"][0], raw["documents"][0],
        raw["metadatas"][0], raw["distances"][0],
    ):
        results.append({
            "id":          cve_id,
            "description": doc,
            "cwe":         meta.get("cwe_primary", "—"),
            "severity":    meta.get("severity", "—"),
            "score":       meta.get("score", "—"),
            "similarity":  round(1 - dist, 4),
        })
    return results


def _format_cve_context(cve_list: list[dict]) -> str:
    """CVE 검색 결과를 프롬프트용 텍스트 블록으로 변환한다."""
    lines = []
    for c in cve_list:
        desc = c["description"][:200].rstrip()
        lines.append(
            f"- {c['id']} ({c['cwe']}, {c['severity']}, CVSS {c['score']}): {desc}"
        )
    return "\n".join(lines)


def build_rag_prompt(language: str, code: str, cve_list: list[dict]) -> str:
    """CVE 컨텍스트 + 코드를 결합한 RAG 프롬프트를 생성한다."""
    cve_context = _format_cve_context(cve_list)
    return (
        f"Reference CVEs (use as context only — focus on the code below):\n{cve_context}\n\n"
        f"Analyze this {language} code for security vulnerabilities.\n\n"
        f"Code:\n{code}\n\n"
        "Respond in this exact format:\n"
        "VULNERABILITY: [vulnerability name with CWE ID]\n"
        "SEVERITY: [CRITICAL/HIGH/MEDIUM/LOW]\n"
        "ATTACK: [attack scenario in one sentence]\n"
        "FIX: [fixed code only, no explanation]"
    )


def analyze(
    language: str,
    code: str,
    n_results: int = 5,
    model: str = DEFAULT_MODEL,
) -> tuple[str, float, list[dict]]:
    """
    RAG 파이프라인 메인 함수.

    Returns:
        (llm_response, elapsed_seconds, retrieved_cves)
    """
    # 코드 단독보다 언어 + 취약점 맥락을 섞어 검색 품질 향상
    search_query = f"{language} security vulnerability: {code}"
    cve_list = search_cve(query=search_query, n_results=n_results)
    prompt   = build_rag_prompt(language, code, cve_list)
    response, elapsed = query_llm(prompt, system_prompt=SECURITY_SYSTEM_PROMPT, model=model)
    return response, elapsed, cve_list


# ── CLI 테스트 ─────────────────────────────────────────────────────────────────

def main():
    test_cases = [
        {
            "language": "Node.js / Express",
            "code":     'db.query("SELECT * FROM users WHERE id=" + req.params.id);',
            "label":    "SQL Injection",
        },
        {
            "language": "Java Spring Boot",
            "code":     "if (password.equals(inputPassword)) { grantAccess(); }",
            "label":    "Timing Attack",
        },
        {
            "language": "GitHub Actions YAML",
            "code":     "- uses: actions/checkout@main  # unpinned version",
            "label":    "Supply Chain Attack",
        },
    ]

    print("=" * 60)
    print("RAG Pipeline 테스트 (ChromaDB + Grok API)")
    print(f"CVE 컬렉션: {CHROMA_DIR} / 모델: {DEFAULT_MODEL}")
    print("=" * 60)

    col, _ = _get_resources()
    print(f"ChromaDB 문서 수: {col.count()}\n")

    for tc in test_cases:
        print(f"[{tc['label']}] {tc['language']}")
        print(f"  코드: {tc['code'][:60]}...")

        response, elapsed, cves = analyze(tc["language"], tc["code"])

        print(f"  검색된 CVE:")
        for c in cves:
            print(f"    {c['id']} ({c['cwe']}, {c['severity']}) sim={c['similarity']}")

        # 응답에서 첫 두 줄만 요약 출력
        summary = "\n  ".join(response.strip().splitlines()[:4])
        print(f"  LLM 응답 ({elapsed}s):\n  {summary}")
        print()


if __name__ == "__main__":
    main()
