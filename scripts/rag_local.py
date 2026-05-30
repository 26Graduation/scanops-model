"""
RAG Pipeline (Local) — Grok 없이 Ollama 모델로 동작
기존 rag_pipeline.py의 grok_client 의존성 제거.

동작 방식:
  1단계: 코드 → Ollama(gemma:2b 또는 LoRA 로드 모델) 단독 탐지
  2단계: 탐지된 CWE → ChromaDB 검색 → 실제 CVE 근거 반환

사용:
  from rag_local import analyze
  result = analyze(language="Python", code="...", model="gemma:2b")
"""

import json
import re
import time
import urllib.request
from pathlib import Path
from typing import Optional

import chromadb
from sentence_transformers import SentenceTransformer

BASE_DIR   = Path(__file__).resolve().parent.parent
CHROMA_DIR = BASE_DIR / "chroma_db"
COLLECTION = "cve_collection"
BGE_MODEL  = "BAAI/bge-small-en-v1.5"
BGE_PREFIX = "Represent this sentence for searching relevant passages: "
OLLAMA_URL = "http://localhost:11434/api/generate"

SIM_THRESHOLD = 0.5

_DETECTION_PROMPT = """\
You are a security code reviewer.
Analyze this {language} code for security vulnerabilities.

Code:
{code}

Respond in this exact format:
VULNERABILITY: [vulnerability name with CWE ID if known]
SEVERITY: [CRITICAL/HIGH/MEDIUM/LOW]
ATTACK: [attack scenario in one sentence]
FIX: [fixed code only, no explanation]"""

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


def _ollama_generate(prompt: str, model: str, timeout: int = 120) -> tuple[str, float]:
    payload = json.dumps({
        "model":  model,
        "prompt": prompt,
        "stream": False,
    }).encode()
    req = urllib.request.Request(
        OLLAMA_URL,
        data=payload,
        headers={"Content-Type": "application/json"},
        method="POST",
    )
    t0 = time.perf_counter()
    with urllib.request.urlopen(req, timeout=timeout) as resp:
        body = json.loads(resp.read())
    elapsed = round(time.perf_counter() - t0, 2)
    return body["response"], elapsed


def _extract_cwe(vuln_text: str) -> Optional[str]:
    m = re.search(r"CWE-\d+", vuln_text, re.IGNORECASE)
    return m.group(0).upper() if m else None


def _build_search_query(vuln_text: str, language: str) -> str:
    cwe = _extract_cwe(vuln_text)
    if cwe:
        return f"{cwe} {vuln_text} {language}"
    return f"{vuln_text} {language} vulnerability"


def _parse_response(text: str) -> dict:
    fields: dict[str, str] = {}
    for key in ("VULNERABILITY", "SEVERITY", "ATTACK", "FIX"):
        m = re.search(
            rf"^\*{{0,2}}{key.lower()}\*{{0,2}}:[ \t]*(.+)",
            text, re.MULTILINE | re.IGNORECASE,
        )
        fields[key] = m.group(1).strip().strip("*").strip() if m else "—"

    m_fix = re.search(r"^\*{0,2}fix\*{0,2}:[ \t]*([\s\S]+)", text, re.MULTILINE | re.IGNORECASE)
    if m_fix:
        raw = m_fix.group(1).strip()
        raw = re.sub(r"^```[^\n]*\n", "", raw).rstrip("`").strip()
        fields["FIX"] = raw

    for k in ("VULNERABILITY", "SEVERITY", "ATTACK"):
        fields[k] = re.sub(r"\*+", "", fields.get(k, "—")).strip()

    return fields


def _search_cves(query: str, n_results: int = 3) -> list[dict]:
    col, embed = _get_resources()
    embedded   = embed.encode(BGE_PREFIX + query).tolist()
    results    = col.query(
        query_embeddings=[embedded],
        n_results=n_results,
        include=["documents", "metadatas", "distances"],
    )
    refs = []
    for doc, meta, dist in zip(
        results["documents"][0],
        results["metadatas"][0],
        results["distances"][0],
    ):
        sim = round(1 - dist, 3)
        if sim >= SIM_THRESHOLD:
            refs.append({
                "cve_id":     meta.get("cve_id", "?"),
                "cwe":        meta.get("cwe", "?"),
                "severity":   meta.get("severity", "?"),
                "score":      meta.get("score", "?"),
                "similarity": sim,
                "description": doc[:300],
            })
    return refs


def analyze(
    language: str,
    code: str,
    model: str = "gemma:2b",
) -> dict:
    """
    코드를 분석하고 CVE 근거를 반환.

    Returns:
        {
          "vulnerability": str,
          "severity": str,
          "attack": str,
          "fix": str,
          "elapsed": float,
          "cve_references": list[dict],
          "model": str,
        }
    """
    # 1단계: 로컬 모델 탐지
    prompt  = _DETECTION_PROMPT.format(language=language, code=code)
    raw, elapsed = _ollama_generate(prompt, model=model)
    parsed  = _parse_response(raw)

    # 2단계: CWE → ChromaDB CVE 검색
    vuln_text = parsed.get("VULNERABILITY", "")
    cve_refs: list[dict] = []
    if vuln_text and vuln_text != "—":
        try:
            query    = _build_search_query(vuln_text, language)
            cve_refs = _search_cves(query)
        except Exception:
            pass

    return {
        "vulnerability":  parsed.get("VULNERABILITY", "—"),
        "severity":       parsed.get("SEVERITY", "—"),
        "attack":         parsed.get("ATTACK", "—"),
        "fix":            parsed.get("FIX", "—"),
        "raw_response":   raw,
        "elapsed":        elapsed,
        "cve_references": cve_refs,
        "model":          model,
    }


def analyze_with_context(
    language: str,
    code: str,
    model: str = "gemma:2b",
    n_context: int = 2,
) -> dict:
    """
    RAG 강화 버전: CVE 컨텍스트를 프롬프트에 포함해 탐지 품질 향상.
    - 1단계: 코드만으로 초기 탐지 → CWE 파악
    - 2단계: 해당 CWE의 실제 CVE 예제를 컨텍스트로 삽입 → 재탐지
    - 주의: 컨텍스트 오염 방지를 위해 탐지 판정은 재탐지 결과 기준
    """
    # 1단계: 초기 탐지
    prompt1  = _DETECTION_PROMPT.format(language=language, code=code)
    raw1, _  = _ollama_generate(prompt1, model=model)
    parsed1  = _parse_response(raw1)
    vuln1    = parsed1.get("VULNERABILITY", "")

    # CVE 검색
    cve_refs: list[dict] = []
    if vuln1 and vuln1 != "—":
        try:
            cve_refs = _search_cves(_build_search_query(vuln1, language), n_results=n_context)
        except Exception:
            pass

    if not cve_refs:
        # CVE 없으면 1단계 결과로 반환 (소문자 키로 통일)
        return {
            "vulnerability":  parsed1.get("VULNERABILITY", "—"),
            "severity":       parsed1.get("SEVERITY", "—"),
            "attack":         parsed1.get("ATTACK", "—"),
            "fix":            parsed1.get("FIX", "—"),
            "raw_response":   raw1,
            "elapsed":        0.0,
            "cve_references": [],
            "model":          model,
        }

    # 2단계: CVE 컨텍스트 포함 재탐지
    cve_ctx = "\n".join(
        f"- {r['cve_id']} ({r['cwe']}): {r['description'][:120]}"
        for r in cve_refs
    )
    prompt2 = (
        _DETECTION_PROMPT.format(language=language, code=code)
        + f"\n\nRelated real-world CVEs for context:\n{cve_ctx}"
    )
    raw2, elapsed = _ollama_generate(prompt2, model=model)
    parsed2       = _parse_response(raw2)

    return {
        "vulnerability":  parsed2.get("VULNERABILITY", "—"),
        "severity":       parsed2.get("SEVERITY", "—"),
        "attack":         parsed2.get("ATTACK", "—"),
        "fix":            parsed2.get("FIX", "—"),
        "raw_response":   raw2,
        "elapsed":        elapsed,
        "cve_references": cve_refs,
        "model":          model,
    }


if __name__ == "__main__":
    import argparse

    parser = argparse.ArgumentParser(description="RAG Local — Ollama 기반 보안 분석")
    parser.add_argument("--model",   default="gemma:2b", help="Ollama 모델명")
    parser.add_argument("--rag",     action="store_true", help="CVE 컨텍스트 포함 재탐지")
    args = parser.parse_args()

    # 빠른 테스트
    test_cases = [
        ("Python",
         "import subprocess\nsubprocess.call(user_input, shell=True)"),
        ("Node.js / Express",
         'db.query("SELECT * FROM users WHERE id=" + req.params.id);'),
        ("React / Next.js",
         'return <div dangerouslySetInnerHTML={{__html: userInput}} />;'),
    ]

    fn = analyze_with_context if args.rag else analyze
    print(f"모델: {args.model}  |  RAG: {args.rag}\n" + "─" * 55)
    for lang, code in test_cases:
        print(f"[{lang}] {code[:60]}")
        result = fn(language=lang, code=code, model=args.model)
        print(f"  취약점: {result['vulnerability']}")
        print(f"  심각도: {result['severity']}")
        print(f"  시간  : {result['elapsed']}s")
        if result["cve_references"]:
            print(f"  CVE근거: {result['cve_references'][0]['cve_id']} (sim={result['cve_references'][0]['similarity']})")
        print()
