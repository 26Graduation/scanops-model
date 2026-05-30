"""ScanOps v3 벤치마크 — QLoRA v3 + Qdrant RAG Adaptive.

v2 결과와 비교하고 최종 탐지율을 JSON으로 저장.

실행:
  cd /Users/kimsehan/Desktop/scanops/scanops-model
  source .venv/bin/activate
  python scripts/benchmark_v3.py
"""

from __future__ import annotations

import json
import sys
from pathlib import Path

BASE_DIR = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(BASE_DIR))
sys.path.insert(0, str(BASE_DIR / "scripts"))

from scripts.benchmark_qwen_rag import (
    run_benchmark,
    run_scanops_adaptive,
    search_cves,
    build_ft_user_prompt,
    build_base_rag_prompt,
    call_model,
    parse_response,
    REPORTS,
)
from scripts.benchmark_core import CASES, detected

MODEL_V3   = "qwen2.5-coder-security-v3:latest"
MODEL_BASE = "qwen2.5-coder:1.5b"


def run_scanops_v3(verbose: bool = True) -> dict:
    """v3 Adaptive: Stage1=v3 QLoRA → Stage2=base+RAG fallback."""
    import time

    results = []
    name    = "ScanOps v3 (QLoRA+RAG Adaptive)"

    if verbose:
        print(f"\n{'='*65}")
        print(f"  {name}")
        print(f"{'='*65}")

    for case in CASES:
        if verbose:
            print(f"[{case['id']:02d}/20] [{case['language']}] {case['expected_vuln']}")
        cves = []
        t0   = time.time()
        try:
            # Stage 1: v3 QLoRA (no RAG)
            content_ft = build_ft_user_prompt(case["language"], case["code"])
            resp_ft, _ = call_model(content_ft, MODEL_V3, is_finetuned=True, timeout=60)
            parsed_ft  = parse_response(resp_ft)

            vuln_ft = parsed_ft.get("VULNERABILITY", "—")
            sev_ft  = parsed_ft.get("SEVERITY", "—")

            _VULN_GARBAGE = (
                "vulnerability:", "last line", "at end of", "at the end",
                "on line ", "in the code", "in the function",
            )

            def _is_valid(txt: str) -> bool:
                if not txt or txt in ("—", "N/A", ""):
                    return False
                t = txt.lower()
                if any(p in t for p in _VULN_GARBAGE):
                    return False
                if txt.count(". ") >= 2:
                    return False
                return True

            ok_ft = _is_valid(vuln_ft) and sev_ft not in ("—", "N/A", "", None)

            if ok_ft:
                cve_q = f"{case['language']} {vuln_ft} {case['code'][:120]}"
                cves  = search_cves(cve_q)
                ok    = detected(parsed_ft, case)
                final = parsed_ft
                stage = 1
            else:
                # Stage 2: base + RAG
                hint  = vuln_ft if _is_valid(vuln_ft) else "security vulnerability"
                cve_q = f"{case['language']} {hint} {case['code'][:120]}"
                cves  = search_cves(cve_q)
                content_b = build_base_rag_prompt(case["language"], case["code"], cves)
                resp_b, _ = call_model(content_b, MODEL_BASE, is_finetuned=False, timeout=60)
                final = parse_response(resp_b)
                ok    = detected(final, case)
                stage = 2

        except Exception as e:
            if verbose:
                print(f"  오류: {e}")
            results.append({
                **case, "response": "", "parsed": {}, "elapsed": 0.0,
                "detected": False, "cve_references": [], "stage": 0, "error": str(e),
            })
            continue

        elapsed = round(time.time() - t0, 2)
        results.append({
            **case,
            "response":       final,
            "parsed":         final,
            "elapsed":        elapsed,
            "detected":       ok,
            "cve_references": cves,
            "stage":          stage,
        })

        if verbose:
            tick  = "✓" if ok else "✗"
            vuln  = final.get("VULNERABILITY", "—")[:48]
            sev   = final.get("SEVERITY", "?")
            print(f"  {tick}  Stage{stage}  {vuln}  [{sev}]  {elapsed}s  CVE×{len(cves)}\n")

    total      = len(results)
    n_detected = sum(1 for r in results if r["detected"])
    valid      = [r for r in results if r.get("elapsed", 0) > 0]
    avg_t      = round(sum(r["elapsed"] for r in valid) / len(valid), 2) if valid else 0
    n_stage1   = sum(1 for r in results if r.get("stage") == 1)
    n_stage2   = sum(1 for r in results if r.get("stage") == 2)

    summary = {
        "model_name": name,
        "model":      MODEL_V3,
        "base_model": MODEL_BASE,
        "use_rag":    True,
        "timestamp":  __import__("datetime").datetime.now().isoformat(),
        "total":      total,
        "detected":   n_detected,
        "detect_pct": round(n_detected / total * 100, 1),
        "avg_time":   avg_t,
        "stage1_count": n_stage1,
        "stage2_count": n_stage2,
        "results":    results,
    }

    out = REPORTS / "results_ScanOps_v3_QLoRAplusRAG_Adaptive.json"
    out.write_text(json.dumps(summary, ensure_ascii=False, indent=2), encoding="utf-8")

    if verbose:
        print("─" * 65)
        print(f"탐지율: {n_detected}/{total} ({summary['detect_pct']}%)")
        print(f"평균 응답: {avg_t}s  |  Stage1: {n_stage1}건  Stage2: {n_stage2}건")
        print(f"저장: {out}")

    return summary


def compare_v2_v3() -> None:
    v2_path = REPORTS / "results_ScanOps_v2_QLoRAplusRAG_Adaptive.json"
    v3_path = REPORTS / "results_ScanOps_v3_QLoRAplusRAG_Adaptive.json"

    if not v2_path.exists() or not v3_path.exists():
        print("비교할 결과 파일이 없습니다.")
        return

    v2 = json.loads(v2_path.read_text())
    v3 = json.loads(v3_path.read_text())

    print("\n" + "=" * 65)
    print("  v2 vs v3 비교")
    print("=" * 65)
    print(f"{'항목':<30} {'v2':>10} {'v3':>10} {'변화':>10}")
    print("─" * 65)

    det_diff = v3['detected'] - v2['detected']
    pct_diff = round(v3['detect_pct'] - v2['detect_pct'], 1)
    spd_diff = round(v3['avg_time'] - v2['avg_time'], 2)

    print(f"{'탐지 케이스 (20개 기준)':<30} {v2['detected']:>10} {v3['detected']:>10} {det_diff:>+10}")
    print(f"{'탐지율 (%)':<30} {v2['detect_pct']:>10} {v3['detect_pct']:>10} {pct_diff:>+10}")
    print(f"{'평균 응답 시간 (s)':<30} {v2['avg_time']:>10} {v3['avg_time']:>10} {spd_diff:>+10}")

    print("\n케이스별 변화:")
    v2_map = {r['id']: r for r in v2['results']}
    v3_map = {r['id']: r for r in v3['results']}
    for id_, r3 in v3_map.items():
        r2 = v2_map.get(id_, {})
        was = "✓" if r2.get("detected") else "✗"
        now = "✓" if r3.get("detected") else "✗"
        if was != now:
            vuln = r3.get("expected_vuln", "?")
            lang = r3.get("language", "?")
            print(f"  [{id_:02d}] {lang} / {vuln}: {was} → {now}")


if __name__ == "__main__":
    run_scanops_v3(verbose=True)
    compare_v2_v3()
