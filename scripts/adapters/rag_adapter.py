"""
ScanOps 어댑터 — RAG Pipeline (ChromaDB + Grok API)

grok_adapter.py(Grok 단독)와의 차이:
  - ChromaDB에서 유사 CVE top-5 검색 후 컨텍스트로 주입
  - 응답에 근거 CVE 목록 포함 (어떤 실제 CVE와 유사한지)
  - 탐지율 향상보다 "CVE 근거 제시"가 목적

실행:
    python scripts/adapters/rag_adapter.py
"""

import json
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from benchmark_core import REPORTS, run_benchmark, save_html
from rag_pipeline import analyze

MODEL_NAME = "ScanOps — RAG (ChromaDB + grok-3)"
MODEL      = "grok-3"


def query(language: str, code: str) -> tuple[str, float]:
    """benchmark_core.QueryFn 인터페이스 구현 (RAG 포함)."""
    response, elapsed, cve_list = analyze(language, code, model=MODEL)
    return response, elapsed


def query_with_evidence(language: str, code: str) -> tuple[str, float, list[dict]]:
    """
    CVE 근거까지 반환하는 확장 함수.
    benchmark_core 표준 인터페이스가 아니므로 직접 호출용.
    """
    return analyze(language, code, model=MODEL)


def run_with_evidence() -> None:
    """CVE 근거 품질 측정 포함 전체 벤치마크 실행."""
    from benchmark_core import CASES, parse_response, detected, PROMPT_TMPL
    from datetime import datetime

    REPORTS.mkdir(exist_ok=True)
    results = []
    print(f"\n[{MODEL_NAME}] 벤치마크 시작 — {len(CASES)}개 케이스")
    print("─" * 60)

    for case in CASES:
        print(f"[{case['id']:02d}/20] [{case['language']}] {case['expected_vuln']}")
        try:
            response, elapsed, cve_list = query_with_evidence(case["language"], case["code"])
        except Exception as e:
            print(f"  오류: {e}\n")
            results.append({**case, "response": "", "parsed": {}, "elapsed": 0.0,
                             "detected": False, "cves": [], "cve_hit": False})
            continue

        parsed   = parse_response(response)
        ok       = detected(parsed, case)
        # CVE 근거 품질: 탐지된 CWE와 top-1 CVE의 CWE가 일치하면 hit
        vuln_cwe = parsed.get("VULNERABILITY", "").lower()
        cve_hit  = bool(cve_list and cve_list[0]["cwe"].lower() in vuln_cwe)

        results.append({**case, "response": response, "parsed": parsed,
                        "elapsed": elapsed, "detected": ok,
                        "cves": cve_list, "cve_hit": cve_hit})

        tick     = "✓" if ok else "✗"
        hit_mark = "🔗" if cve_hit else "  "
        top_cve  = cve_list[0]["id"] if cve_list else "—"
        top_sim  = cve_list[0]["similarity"] if cve_list else 0
        print(f"  {tick} {parsed.get('VULNERABILITY','?')[:45]}  [{parsed.get('SEVERITY','?')}]  {elapsed}s")
        print(f"  {hit_mark} top CVE: {top_cve} (sim={top_sim})\n")

    valid      = [r for r in results if r["elapsed"] > 0]
    n_det      = sum(1 for r in results if r["detected"])
    n_cve_hit  = sum(1 for r in results if r["cve_hit"])
    total      = len(results)
    avg_t      = round(sum(r["elapsed"] for r in valid) / len(valid), 2) if valid else 0
    avg_sim    = round(sum(r["cves"][0]["similarity"] for r in results if r.get("cves")) /
                       max(sum(1 for r in results if r.get("cves")), 1), 3)

    summary = {
        "model_name":    MODEL_NAME,
        "timestamp":     datetime.now().isoformat(),
        "total":         total,
        "detected":      n_det,
        "detect_pct":    round(n_det / total * 100, 1),
        "avg_time":      avg_t,
        # RAG 전용 지표
        "cve_hit":       n_cve_hit,
        "cve_hit_pct":   round(n_cve_hit / total * 100, 1),
        "avg_similarity": avg_sim,
        "results":       results,
    }

    out_json = REPORTS / "results_RAG_grok3.json"
    out_json.write_text(json.dumps(summary, ensure_ascii=False, indent=2), encoding="utf-8")

    out_html = save_html(summary)

    print("─" * 60)
    print(f"탐지율:          {n_det}/{total} ({summary['detect_pct']}%)")
    print(f"CVE CWE 일치율: {n_cve_hit}/{total} ({summary['cve_hit_pct']}%)  ← RAG 근거 품질")
    print(f"평균 CVE 유사도: {avg_sim}")
    print(f"평균 응답시간:   {avg_t}s")
    print(f"JSON: {out_json}")
    print(f"HTML: {out_html}")


if __name__ == "__main__":
    run_with_evidence()
