"""
ScanOps — Qwen 계열 모델 벤치마크 (Qdrant RAG 포함)

실행 대상:
  1. qwen2.5-coder:1.5b (base, no RAG)       → 기존값 확인용 재실행
  2. qwen2.5-coder:1.5b + Qdrant RAG         → 실제 ScanOps 시스템
  3. qwen2.5-coder-security-v2 (QLoRA, no RAG)  → 파인튜닝 단독 성능
  4. qwen2.5-coder-security-v2 + Qdrant RAG     → 파인튜닝 + RAG 최종 성능

사용법:
  cd /Users/kimsehan/Desktop/scanops/scanops-model
  python scripts/benchmark_qwen_rag.py
"""

import json
import sys
import time
from pathlib import Path

import requests
try:  # RAG 전용 의존성 — V17 CPU 서빙 이미지엔 없어도 됨(search_cves만 비활성)
    from qdrant_client import QdrantClient
except ImportError:  # pragma: no cover
    QdrantClient = None

BASE_DIR = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(BASE_DIR))
sys.path.insert(0, str(BASE_DIR / "scripts"))

from scripts.benchmark_core import CASES, parse_response, detected, REPORTS  # noqa

# ── 설정 ───────────────────────────────────────────────────────────────────────
import os

_OLLAMA_BASE    = os.environ.get("OLLAMA_URL", "http://localhost:11434")
OLLAMA_GENERATE = f"{_OLLAMA_BASE}/api/generate"
OLLAMA_CHAT     = f"{_OLLAMA_BASE}/api/chat"
QDRANT_URL      = os.environ.get("QDRANT_URL", "http://localhost:6333")
COLLECTION      = "cve_vulnerabilities"
BGE_MODEL       = "BAAI/bge-small-en-v1.5"

_FINETUNED_PREFIXES = ("qwen2.5-coder-security", "gemma2-security")

# ── 임베더 ──────────────────────────────────────────────────────────────────────

_embed_model = None

def get_embed_model():
    global _embed_model
    if _embed_model is None:
        from sentence_transformers import SentenceTransformer
        _embed_model = SentenceTransformer(BGE_MODEL)
    return _embed_model


def embed_query(text: str) -> list[float]:
    return get_embed_model().encode(text, normalize_embeddings=True).tolist()


# ── Qdrant CVE 검색 ─────────────────────────────────────────────────────────────

_qdrant = None

def get_qdrant():
    global _qdrant
    if _qdrant is None:
        _qdrant = QdrantClient(url=QDRANT_URL)
    return _qdrant


def search_cves(query: str, top_k: int = 3) -> list[dict]:
    """Qdrant CVE 검색 — Qdrant 미연결 시 빈 목록 반환 (Railway 환경 등)."""
    try:
        vec = embed_query(query)
        results = get_qdrant().query_points(
            collection_name=COLLECTION,
            query=vec,
            limit=top_k,
            with_payload=True,
        ).points
        return [
            {
                "score":       r.score,
                "cve_id":      r.payload.get("cve_id", "N/A"),
                "severity":    r.payload.get("severity", "N/A"),
                "base_score":  r.payload.get("base_score", 0),
                "cwe_id":      r.payload.get("cwe_id", "N/A"),
                "description": r.payload.get("description", "")[:200],
            }
            for r in results
        ]
    except Exception:
        # Qdrant 미연결(Railway 초기 환경 등)이면 RAG 없이 진행
        return []


# ── 프롬프트 빌더 ──────────────────────────────────────────────────────────────

SYSTEM_BASE = "You are a security code reviewer. Always identify the specific vulnerability in the code."
SYSTEM_FT   = (
    "You are a security code analyzer. "
    "Always respond in EXACTLY this format, starting with VULNERABILITY on the first line:\n"
    "VULNERABILITY: [vulnerability name with CWE ID]\n"
    "SEVERITY: [CRITICAL/HIGH/MEDIUM/LOW]\n"
    "CVSS: [CVSS base score, e.g. 9.8]\n"
    "ATTACK: [한 문장으로 공격 시나리오 설명 (반드시 한국어)]\n"
    "FIX: [수정된 코드. 코드가 없으면 한국어로 해결 방법 설명]"
)

OUTPUT_FORMAT = """\
First decide whether the code has a REAL, exploitable security vulnerability.

If the code is SAFE (no real vulnerability — e.g. parameterized queries, output \
escaping, input validation, strong crypto/hash, secure randomness, proper auth \
checks already present), respond with EXACTLY one line:
VULNERABILITY: NONE

If the code DOES have a real vulnerability, list ALL of them. For EACH \
vulnerability, use EXACTLY this format, separated by ---:
VULNERABILITY: [vulnerability name with CWE ID]
SEVERITY: [CRITICAL/HIGH/MEDIUM/LOW]
CVSS: [CVSS base score, e.g. 9.8]
ATTACK: [한 문장으로 공격 시나리오 설명 (반드시 한국어)]
FIX: [수정된 코드. 코드가 없으면 한국어로 해결 방법 설명]
---"""


def _cve_block(cves: list[dict]) -> str:
    if not cves:
        return "No relevant CVEs found."
    lines = []
    for c in cves:
        lines.append(
            f"- {c['cve_id']} ({c['severity']}, CVSS {c['base_score']}, {c['cwe_id']}): "
            f"{c['description']}"
        )
    return "\n".join(lines)


def build_base_prompt(language: str, code: str) -> str:
    return (
        f"Analyze this {language} code for security vulnerabilities.\n\n"
        f"Code:\n{code}\n\n"
        f"{OUTPUT_FORMAT}"
    )


def build_base_rag_prompt(language: str, code: str, cves: list[dict]) -> str:
    # Code FIRST so model forms opinion from code, CVE context is supplementary
    return (
        f"Analyze this {language} code for security vulnerabilities.\n\n"
        f"Code:\n{code}\n\n"
        f"Supplementary CVE references (use only if relevant to the code above):\n"
        f"{_cve_block(cves)}\n\n"
        f"{OUTPUT_FORMAT}"
    )


def _lang_hint(language: str) -> str:
    s = language.lower()
    if "react" in s: return "jsx"
    if "node" in s: return "js"
    if "java" in s: return "java"
    if "python" in s: return "python"
    if "yaml" in s or "github" in s: return "yaml"
    if s.strip() == "c": return "c"
    return "text"


def build_ft_user_prompt(language: str, code: str) -> str:
    hint = _lang_hint(language)
    return (
        f"Analyze this {language} code for security vulnerabilities:\n\n"
        f"```{hint}\n{code}\n```\n\n"
        f"{OUTPUT_FORMAT}"
    )


def build_ft_rag_user_prompt(language: str, code: str, cves: list[dict]) -> str:
    hint = _lang_hint(language)
    return (
        f"Analyze this {language} code for security vulnerabilities.\n\n"
        f"```{hint}\n{code}\n```\n\n"
        f"Supplementary CVE references:\n{_cve_block(cves)}\n\n"
        f"Respond starting with VULNERABILITY: on the first line."
    )


# ── LLM 호출 ───────────────────────────────────────────────────────────────────

def _call_base(prompt: str, model: str, timeout: int = 90) -> tuple[str, float]:
    """/api/generate — base 모델용."""
    payload = {
        "model":  model,
        "prompt": prompt,
        "system": SYSTEM_BASE,
        "stream": False,
        "options": {
            "temperature":    0.1,
            "top_p":          0.9,
            "num_predict":    400,
            "stop":           ["<|im_end|>", "<|endoftext|>"],
            "repeat_penalty": 1.1,
        },
    }
    t0 = time.time()
    resp = requests.post(OLLAMA_GENERATE, json=payload, timeout=timeout)
    elapsed = round(time.time() - t0, 2)
    resp.raise_for_status()
    return resp.json().get("response", "").strip(), elapsed


def _call_finetuned(user_content: str, model: str, timeout: int = 90) -> tuple[str, float]:
    """/api/chat — 파인튜닝 모델용 (chat template을 Ollama가 처리)."""
    payload = {
        "model":  model,
        "messages": [
            {"role": "system",    "content": SYSTEM_FT},
            {"role": "user",      "content": user_content},
        ],
        "stream": False,
        "options": {
            "temperature":    0.0,   # 결정적(재현 가능)
            "top_p":          0.8,
            "num_predict":    200,   # 3줄 구조화 출력(+프리앰블)엔 충분; 400→200로 추론 단축
            # 주의: "\n\n\n" stop 금지 — v12는 답 앞에 '--- ---\n\n\n' 프리앰블을
            # 붙이는 습관이 있어, 이 stop이 진짜 VULNERABILITY: 줄 전에 출력을 잘라버린다.
            # 대신 아래 cleanup이 VULNERABILITY: 위치부터 추출한다.
            "stop":           ["<|im_end|>", "<|endoftext|>", "[EMPTY_151643]"],
            "repeat_penalty": 1.3,
        },
    }
    t0 = time.time()
    # RUNPOD_ENDPOINT_ID 설정 시 RunPod serverless 경유 (미설정 시 로컬 Ollama — 동작 동일)
    from scanops.core.llm_client import chat as _llm_chat
    raw = _llm_chat(payload["model"], payload["messages"], payload["options"], timeout=timeout)
    elapsed = round(time.time() - t0, 2)
    # sentinel cleanup — 모델이 출력하는 garbage 패턴 제거
    for sentinel in ("[EMPTY_", "Human resources", "The following", "Note:", "\nVULNERABILITY_FIXED:"):
        idx = raw.find(sentinel)
        if idx != -1:
            raw = raw[:idx]
    # VULNERABILITY: 이전 garbage 텍스트 제거 (모델이 SOLUTION: 등을 앞에 붙이는 경우)
    vuln_idx = raw.find("VULNERABILITY:")
    if vuln_idx > 0:
        raw = raw[vuln_idx:]
    return raw.strip(), elapsed


def call_model(prompt_or_content: str, model: str, is_finetuned: bool, timeout: int = 90) -> tuple[str, float]:
    if is_finetuned:
        return _call_finetuned(prompt_or_content, model, timeout)
    else:
        return _call_base(prompt_or_content, model, timeout)


# ── 단일 모델 벤치마크 실행 ────────────────────────────────────────────────────

def run_benchmark(
    model: str,
    use_rag: bool,
    name: str,
    verbose: bool = True,
) -> dict:
    is_finetuned = any(model.startswith(p) for p in _FINETUNED_PREFIXES)
    results = []

    if verbose:
        tag = "+RAG" if use_rag else "     "
        print(f"\n[{name}]  모델: {model}  {tag}")
        print("─" * 65)

    for case in CASES:
        if verbose:
            print(f"[{case['id']:02d}/20] [{case['language']}] {case['expected_vuln']}")
        try:
            if use_rag:
                cve_query = f"{case['language']} {case['expected_vuln']} {case['code'][:120]}"
                cves = search_cves(cve_query)
                content = (
                    build_ft_rag_user_prompt(case["language"], case["code"], cves)
                    if is_finetuned
                    else build_base_rag_prompt(case["language"], case["code"], cves)
                )
            else:
                cves = []
                content = (
                    build_ft_user_prompt(case["language"], case["code"])
                    if is_finetuned
                    else build_base_prompt(case["language"], case["code"])
                )

            response, elapsed = call_model(content, model, is_finetuned)
        except Exception as e:
            if verbose:
                print(f"  오류: {e}\n")
            results.append({
                **case, "response": "", "parsed": {},
                "elapsed": 0.0, "detected": False,
                "cve_references": [], "error": str(e),
            })
            continue

        parsed = parse_response(response)
        ok     = detected(parsed, case)
        # Finetuned 모델 폴백: 파싱 실패 시 raw 응답에서 accepted 키워드 검색
        if not ok and is_finetuned and response:
            raw_lower = response.lower()
            accepted  = [a.lower() for a in case.get("accepted", [])]
            ok = accepted and any(a in raw_lower for a in accepted)
        results.append({
            **case,
            "response":       response,
            "parsed":         parsed,
            "elapsed":        elapsed,
            "detected":       ok,
            "cve_references": cves if use_rag else [],
        })

        if verbose:
            tick = "✓" if ok else "✗"
            sev  = parsed.get("SEVERITY", "?")
            vuln = parsed.get("VULNERABILITY", response[:40])[:48]
            cve_tag = f"  CVE×{len(cves)}" if use_rag else ""
            print(f"  {tick} {vuln}  [{sev}]  {elapsed}s{cve_tag}\n")

    total      = len(results)
    n_detected = sum(1 for r in results if r["detected"])
    valid      = [r for r in results if r.get("elapsed", 0) > 0]
    avg_t      = round(sum(r["elapsed"] for r in valid) / len(valid), 2) if valid else 0

    summary = {
        "model_name":  name,
        "model":       model,
        "use_rag":     use_rag,
        "timestamp":   __import__("datetime").datetime.now().isoformat(),
        "total":       total,
        "detected":    n_detected,
        "detect_pct":  round(n_detected / total * 100, 1),
        "avg_time":    avg_t,
        "results":     results,
    }

    safe = name.replace(" ", "_").replace("/", "-").replace("(", "").replace(")", "").replace("+", "plus")
    out  = REPORTS / f"results_{safe}.json"
    out.write_text(json.dumps(summary, ensure_ascii=False, indent=2), encoding="utf-8")

    if verbose:
        print("─" * 65)
        print(f"탐지율: {n_detected}/{total} ({summary['detect_pct']}%)   평균: {avg_t}s")
        print(f"저장: {out}")

    return summary


# ── ScanOps 어댑티브 시스템 (QLoRA primary + base RAG fallback) ────────────────

MODEL_FT   = "qwen2.5-coder-security-v2:latest"
MODEL_BASE = "qwen2.5-coder:1.5b"


def _raw_detected(response: str, case: dict) -> bool:
    if not response:
        return False
    raw_lower = response.lower()
    accepted  = [a.lower() for a in case.get("accepted", [])]
    return bool(accepted and any(a in raw_lower for a in accepted))


def run_scanops_adaptive(name: str = "ScanOps v2 (QLoRA+RAG Adaptive)", verbose: bool = True) -> dict:
    """
    2-stage adaptive detection:
      Stage 1: QLoRA finetuned (code-specialist, no RAG) — fast, high-precision
      Stage 2: Base model + Qdrant RAG — fallback for missed cases
    This maximises detection while keeping CVE reference enrichment for all results.
    """
    results = []

    if verbose:
        print(f"\n[{name}]")
        print("─" * 65)

    for case in CASES:
        if verbose:
            print(f"[{case['id']:02d}/20] [{case['language']}] {case['expected_vuln']}")
        cves: list[dict] = []
        try:
            # ── Stage 1: finetuned (no RAG) ──────────────────────────────────
            content_ft = build_ft_user_prompt(case["language"], case["code"])
            resp_ft, t_ft = call_model(content_ft, MODEL_FT, is_finetuned=True)
            parsed_ft = parse_response(resp_ft)
            ok_ft = detected(parsed_ft, case) or _raw_detected(resp_ft, case)

            if ok_ft:
                cve_q = f"{case['language']} {case['expected_vuln']} {case['code'][:120]}"
                cves  = search_cves(cve_q)
                results.append({
                    **case,
                    "response":       resp_ft,
                    "parsed":         parsed_ft,
                    "elapsed":        t_ft,
                    "detected":       True,
                    "cve_references": cves,
                    "stage":          1,
                })
                if verbose:
                    sev  = parsed_ft.get("SEVERITY", "?")
                    vuln = parsed_ft.get("VULNERABILITY", resp_ft[:40])[:48]
                    print(f"  ✓ {vuln}  [{sev}]  {t_ft}s  [FT]\n")
                continue

            # ── Stage 2: base + RAG fallback ─────────────────────────────────
            cve_q  = f"{case['language']} {case['expected_vuln']} {case['code'][:120]}"
            cves   = search_cves(cve_q)
            content_b = build_base_rag_prompt(case["language"], case["code"], cves)
            resp_b, t_b = call_model(content_b, MODEL_BASE, is_finetuned=False)
            parsed_b = parse_response(resp_b)
            ok_b = detected(parsed_b, case)

            total_t = round(t_ft + t_b, 2)
            results.append({
                **case,
                "response":       resp_b,
                "parsed":         parsed_b,
                "elapsed":        total_t,
                "detected":       ok_b,
                "cve_references": cves,
                "stage":          2,
            })
            if verbose:
                tick = "✓" if ok_b else "✗"
                sev  = parsed_b.get("SEVERITY", "?")
                vuln = parsed_b.get("VULNERABILITY", resp_b[:40])[:48]
                print(f"  {tick} {vuln}  [{sev}]  {total_t}s  [base+RAG]\n")

        except Exception as e:
            if verbose:
                print(f"  오류: {e}\n")
            results.append({
                **case, "response": "", "parsed": {},
                "elapsed": 0.0, "detected": False,
                "cve_references": cves, "stage": 0, "error": str(e),
            })

    total      = len(results)
    n_detected = sum(1 for r in results if r["detected"])
    valid      = [r for r in results if r.get("elapsed", 0) > 0]
    avg_t      = round(sum(r["elapsed"] for r in valid) / len(valid), 2) if valid else 0

    summary = {
        "model_name":  name,
        "model":       f"{MODEL_FT}+{MODEL_BASE}(fallback)",
        "use_rag":     True,
        "timestamp":   __import__("datetime").datetime.now().isoformat(),
        "total":       total,
        "detected":    n_detected,
        "detect_pct":  round(n_detected / total * 100, 1),
        "avg_time":    avg_t,
        "results":     results,
    }

    safe = name.replace(" ", "_").replace("/", "-").replace("(", "").replace(")", "").replace("+", "plus")
    out  = REPORTS / f"results_{safe}.json"
    out.write_text(json.dumps(summary, ensure_ascii=False, indent=2), encoding="utf-8")

    if verbose:
        stage_counts = {1: 0, 2: 0}
        for r in results:
            stage_counts[r.get("stage", 1)] = stage_counts.get(r.get("stage", 1), 0) + 1
        print("─" * 65)
        print(f"탐지율: {n_detected}/{total} ({summary['detect_pct']}%)   평균: {avg_t}s")
        print(f"  Stage 1 (QLoRA): {stage_counts.get(1,0)}건  Stage 2 (base+RAG): {stage_counts.get(2,0)}건")
        print(f"저장: {out}")

    return summary


# ── 메인 ───────────────────────────────────────────────────────────────────────

def main():
    print("=" * 65)
    print("ScanOps Benchmark — Qwen 계열 + Qdrant RAG")
    print("=" * 65)

    benchmarks = [
        # (model, use_rag, name)
        ("qwen2.5-coder:1.5b",               False, "Qwen2.5-Coder-1.5B (base, no RAG)"),
        ("qwen2.5-coder:1.5b",               True,  "Qwen2.5-Coder-1.5B + Qdrant RAG"),
        ("qwen2.5-coder-security-v2:latest", False, "Qwen QLoRA v2 (fine-tuned, no RAG)"),
        ("qwen2.5-coder-security-v2:latest", True,  "Qwen QLoRA v2 + Qdrant RAG"),
    ]

    all_results = []
    for model, use_rag, name in benchmarks:
        summary = run_benchmark(model=model, use_rag=use_rag, name=name)
        all_results.append(summary)

    # ScanOps 어댑티브 시스템 (최종 통합 벤치마크)
    adaptive = run_scanops_adaptive()
    all_results.append(adaptive)

    print("\n" + "=" * 65)
    print("전체 결과 요약")
    print("=" * 65)
    print(f"{'모델':<45} {'탐지율':>8} {'평균응답':>10}")
    print("─" * 65)

    existing = [
        {"model_name": "Gemma:2b (base)",                        "detect_pct": 90.0, "avg_time": 4.29},
        {"model_name": "Grok-3 API (비교 기준)",                    "detect_pct": 95.0, "avg_time": 17.66},
        {"model_name": "ScanOps RAG v2 (Qdrant+Grok-3)",         "detect_pct": 100.0, "avg_time": 5.45},
    ]
    for r in existing:
        print(f"  {r['model_name']:<43} {r['detect_pct']:>6.1f}%  {r['avg_time']:>8.2f}s")

    print("─" * 65)
    for s in all_results:
        print(f"  {s['model_name']:<43} {s['detect_pct']:>6.1f}%  {s['avg_time']:>8.2f}s")

    combined = existing + [
        {"model_name": s["model_name"], "detect_pct": s["detect_pct"], "avg_time": s["avg_time"]}
        for s in all_results
    ]
    out = REPORTS / "benchmark_all_results.json"
    out.write_text(json.dumps(combined, ensure_ascii=False, indent=2), encoding="utf-8")
    print(f"\n통합 결과 저장: {out}")


if __name__ == "__main__":
    main()
