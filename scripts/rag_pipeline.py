"""
RAG Pipeline for ScanOps — 2단계 파이프라인 (v2)

[이전 구조의 문제]
코드 → CVE 검색 → CVE 컨텍스트 포함해서 Grok 호출
→ ChromaDB에 편중된 CWE(CWE-284 등)가 LLM 판단을 오염시켜 탐지율 하락

[변경된 구조]
1단계: 코드 → Grok 단독 탐지 (CVE 컨텍스트 없음) → 취약점/CWE 파악
2단계: 탐지된 CWE + 취약점명 → ChromaDB 검색 → 근거 CVE 반환

탐지율은 1단계 결과로만 판정 → CVE 오염 없음
CVE는 근거 자료로만 활용 → "이 취약점과 유사한 실제 CVE들"
"""

import re
import sys
from pathlib import Path

import chromadb
from sentence_transformers import SentenceTransformer

sys.path.insert(0, str(Path(__file__).resolve().parent))
from grok_client import DEFAULT_MODEL, SECURITY_SYSTEM_PROMPT, query_llm

BASE_DIR   = Path(__file__).resolve().parent.parent
CHROMA_DIR = BASE_DIR / "chroma_db"
COLLECTION = "cve_collection"
BGE_MODEL  = "BAAI/bge-small-en-v1.5"
BGE_PREFIX = "Represent this sentence for searching relevant passages: "

SIM_THRESHOLD = 0.5  # 이 미만은 cve_references에서 제외

# 1단계용 프롬프트 — CVE 컨텍스트 없이 순수 탐지
_DETECTION_PROMPT = """\
You are a security code reviewer.
Analyze this {language} code for security vulnerabilities.

Code:
{code}

Respond in this exact format:
VULNERABILITY: [vulnerability name with CWE ID if known]
SEVERITY: [CRITICAL/HIGH/MEDIUM/LOW]
ATTACK: [attack scenario in one sentence]
FIX: [fixed code only, no explanation]\
"""

# ── 싱글톤 리소스 ──────────────────────────────────────────────────────────────

_chroma_col  = None
_embed_model = None


def _get_resources():
    global _chroma_col, _embed_model
    if _chroma_col is None:
        client      = chromadb.PersistentClient(path=str(CHROMA_DIR))
        _chroma_col = client.get_collection(COLLECTION)
    if _embed_model is None:
        _embed_model = SentenceTransformer(BGE_MODEL)
    return _chroma_col, _embed_model


# ── 유틸 ───────────────────────────────────────────────────────────────────────

def _extract_cwe(vuln_text: str) -> str | None:
    """취약점 텍스트에서 첫 번째 CWE 번호를 추출한다."""
    m = re.search(r"CWE-\d+", vuln_text, re.IGNORECASE)
    return m.group(0).upper() if m else None


def _build_search_query(vuln_text: str, language: str) -> str:
    """
    1단계 탐지 결과로 CVE 검색 쿼리를 만든다.
    CWE가 있으면 CWE 번호를 쿼리 앞에 붙여 검색 품질 향상.
    """
    cwe = _extract_cwe(vuln_text)
    # CWE 번호와 취약점 설명 조합 → ChromaDB 유사도 향상
    if cwe:
        # "CWE-89 SQL Injection" 처럼 CWE 설명도 함께 넣음
        vuln_clean = re.sub(r"\(CWE-\d+\)", "", vuln_text).strip(" :-")
        return f"{cwe} {vuln_clean}"
    # CWE 없으면 취약점명 + 언어로 fallback
    return f"{language} {vuln_text}"


# ── 2단계: CVE 검색 ────────────────────────────────────────────────────────────

def search_cve(query: str, n_results: int = 3) -> list[dict]:
    """쿼리로 ChromaDB에서 유사 CVE를 검색한다."""
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


# ── 메인 파이프라인 ────────────────────────────────────────────────────────────

def analyze(
    language: str,
    code: str,
    n_results: int = 3,
    model: str = DEFAULT_MODEL,
    sim_threshold: float = SIM_THRESHOLD,
) -> dict:
    """
    2단계 RAG 파이프라인.

    Returns:
        {
            "vulnerability": str,
            "severity":      str,
            "attack":        str,
            "fix":           str,
            "elapsed":       float,   # 1단계 LLM 응답시간
            "raw_response":  str,     # 1단계 원문
            "cve_references": [       # 2단계 결과 (유사도 threshold 이상만)
                {
                    "id":          str,
                    "cwe":         str,
                    "severity":    str,
                    "score":       float,
                    "similarity":  float,
                    "description": str,
                }
            ]
        }
    """
    # ── 1단계: Grok 단독 탐지 (CVE 컨텍스트 없음) ─────────────────────────────
    prompt   = _DETECTION_PROMPT.format(language=language, code=code)
    response, elapsed = query_llm(
        prompt,
        system_prompt=SECURITY_SYSTEM_PROMPT,
        model=model,
    )

    # 응답 파싱
    parsed = _parse_response(response)

    # ── 2단계: 탐지 결과로 CVE 검색 ──────────────────────────────────────────
    vuln_text    = parsed.get("VULNERABILITY", "")
    search_query = _build_search_query(vuln_text, language)

    raw_cves = search_cve(search_query, n_results=n_results)
    # 유사도 threshold 미만 제거
    cve_refs = [c for c in raw_cves if c["similarity"] >= sim_threshold]

    return {
        "vulnerability":  parsed.get("VULNERABILITY", "—"),
        "severity":       parsed.get("SEVERITY", "—"),
        "attack":         parsed.get("ATTACK", "—"),
        "fix":            parsed.get("FIX", "—"),
        "elapsed":        elapsed,
        "raw_response":   response,
        "cve_references": cve_refs,
    }


def _parse_response(text: str) -> dict:
    """LLM 응답에서 구조화된 필드를 추출한다."""
    KEY_ALIASES = {
        "VULNERABILITY": r"(?:vulnerability|vuln)",
        "SEVERITY":      r"severity",
        "ATTACK":        r"attack",
        "FIX":           r"fix",
    }
    fields = {}
    for canonical, pattern in KEY_ALIASES.items():
        m = re.search(
            rf"^\*{{0,2}}{pattern}\*{{0,2}}:[ \t]*(.+)",
            text, re.MULTILINE | re.IGNORECASE,
        )
        fields[canonical] = m.group(1).strip().strip("*").strip() if m else "—"

    m_fix = re.search(
        r"^\*{0,2}fix\*{0,2}:[ \t]*([\s\S]+)", text, re.MULTILINE | re.IGNORECASE
    )
    if m_fix:
        raw = re.sub(r"^```[^\n]*\n", "", m_fix.group(1).strip()).rstrip("`").strip()
        fields["FIX"] = raw

    for k in ("VULNERABILITY", "SEVERITY", "ATTACK"):
        fields[k] = re.sub(r"\*+", "", fields[k]).strip()

    return fields


# ── CLI 테스트 ─────────────────────────────────────────────────────────────────

def main():
    test_cases = [
        {
            "language": "Node.js / Express",
            "code":     "res.setHeader('Access-Control-Allow-Origin', '*');",
            "label":    "Insecure CORS  ← 이전에 CVE 오염으로 잘못 분류된 케이스",
        },
        {
            "language": "Java Spring Boot",
            "code":     "if (password.equals(inputPassword)) { grantAccess(); }",
            "label":    "Timing Attack  ← 이전에 불안정했던 케이스",
        },
        {
            "language": "Node.js / Express",
            "code":     'db.query("SELECT * FROM users WHERE id=" + req.params.id);',
            "label":    "SQL Injection  ← CVE 근거 잘 나오는지 확인",
        },
    ]

    col, _ = _get_resources()
    print(f"{'='*60}")
    print(f"RAG Pipeline v2 테스트 (2단계 파이프라인)")
    print(f"ChromaDB: {col.count()}개 CVE  |  모델: {DEFAULT_MODEL}")
    print(f"{'='*60}\n")

    for tc in test_cases:
        print(f"[{tc['label']}]")
        print(f"  코드: {tc['code'][:70]}\n")

        result = analyze(tc["language"], tc["code"])

        print(f"  1단계 탐지 ({result['elapsed']}s):")
        print(f"    VULNERABILITY : {result['vulnerability']}")
        print(f"    SEVERITY      : {result['severity']}")
        print(f"    ATTACK        : {result['attack'][:80]}")

        refs = result["cve_references"]
        if refs:
            print(f"\n  2단계 CVE 근거 ({len(refs)}개):")
            for c in refs:
                print(f"    {c['id']} ({c['cwe']}, {c['severity']}) sim={c['similarity']}")
                print(f"      {c['description'][:90]}...")
        else:
            print(f"\n  2단계 CVE 근거: 없음 (threshold={SIM_THRESHOLD} 미만)")
        print()


if __name__ == "__main__":
    main()
