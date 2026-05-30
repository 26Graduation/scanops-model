"""
ScanOps v4 벤치마크 — QLoRA v4 + Qdrant RAG Adaptive (40 케이스)
==================================================================
v2/v3 결과와 비교 + CVSS 필드 포함 최종 탐지율 JSON 저장.

실행:
  cd /Users/kimsehan/Desktop/scanops/scanops-model
  source .venv/bin/activate
  python scripts/benchmark_v4.py
"""

from __future__ import annotations

import json
import sys
import time
from pathlib import Path

BASE_DIR = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(BASE_DIR))
sys.path.insert(0, str(BASE_DIR / "scripts"))

from scripts.benchmark_qwen_rag import (
    build_ft_user_prompt,
    build_base_rag_prompt,
    call_model,
    parse_response,
    search_cves,
    REPORTS,
)
from scripts.benchmark_core import CASES, detected

MODEL_V4   = "qwen2.5-coder-security-v4:latest"
MODEL_BASE = "qwen2.5-coder:1.5b"

# v2/v3 이전 결과 (비교용)
V2_RESULTS_PATH = REPORTS / "results_ScanOps_v2_QLoRAplusRAG_Adaptive.json"
V3_RESULTS_PATH = REPORTS / "results_ScanOps_v3_QLoRAplusRAG_Adaptive.json"


def _is_valid_vuln(vuln: str) -> bool:
    if not vuln or vuln in ("—", "N/A", ""):
        return False
    garbage = ("vulnerability:", "last line", "at end of", "at the end",
               "on line ", "in the code", "in the function",
               "the vulnerability is", "this vulnerability")
    tl = vuln.lower()
    if any(p in tl for p in garbage):
        return False
    if vuln.count(". ") >= 2:
        return False
    return True


def run_scanops_v4(verbose: bool = True) -> dict:
    """v4 Adaptive: Stage1=v4 QLoRA → Stage2=base+RAG fallback."""
    results = []
    name    = "ScanOps v4 (QLoRA+RAG Adaptive)"

    if verbose:
        print(f"\n{'='*65}")
        print(f"  {name}")
        print(f"{'='*65}")

    for case in CASES:
        if verbose:
            print(f"[{case['id']:02d}/{len(CASES)}] [{case['language']}] {case['expected_vuln']}")

        t0 = time.time()
        cves: list[dict] = []

        # Stage 1: v4 QLoRA
        try:
            content_ft = build_ft_user_prompt(case["language"], case["code"])
            resp_ft, _ = call_model(content_ft, MODEL_V4, is_finetuned=True, timeout=60)
            parsed_ft  = parse_response(resp_ft)
        except Exception:
            resp_ft, parsed_ft = "", {"VULNERABILITY": "—", "SEVERITY": "—",
                                       "CVSS": "—", "ATTACK": "—", "FIX": "—"}

        vuln_ft = parsed_ft.get("VULNERABILITY", "—")
        sev_ft  = parsed_ft.get("SEVERITY",      "—")
        # raw 텍스트에서도 accepted 키워드 체크 (포맷 불량 응답 구제)
        _accepted_lc = [a.lower() for a in case.get("accepted", [])]
        _raw_ok = bool(resp_ft and _accepted_lc and
                       any(a in resp_ft.lower() for a in _accepted_lc))
        # Stage1 성공 조건: 예상 취약점 탐지 OR raw 텍스트 매칭 OR (유효한 vuln명 + severity)
        ok_ft   = (detected(parsed_ft, case) or _raw_ok or
                   (_is_valid_vuln(vuln_ft) and sev_ft not in ("—", "N/A", "", None)))
        stage   = 1
        final   = parsed_ft

        if ok_ft:
            cve_q = f"{case['language']} {vuln_ft} {case['code'][:120]}"
            cves  = search_cves(cve_q)
        else:
            stage = 2
            hint  = vuln_ft if vuln_ft not in ("—", "N/A", "", None) else "security vulnerability"
            cve_q = f"{case['language']} {hint} {case['code'][:120]}"
            cves  = search_cves(cve_q)
            try:
                content_b = build_base_rag_prompt(case["language"], case["code"], cves)
                resp_b, _ = call_model(content_b, MODEL_BASE, is_finetuned=False, timeout=60)
                final = parse_response(resp_b)
            except Exception:
                pass

        elapsed = round(time.time() - t0, 2)
        ok      = detected(final, case)
        # Stage1에서 포맷 불량이지만 raw 텍스트에 키워드 있는 경우 구제
        if stage == 1 and not ok:
            ok = _raw_ok
        cvss    = final.get("CVSS", "—")

        if verbose:
            tick = "✓" if ok else "✗"
            sev  = final.get("SEVERITY", "?")
            vuln = final.get("VULNERABILITY", "?")[:48]
            cvss_str = f"  CVSS:{cvss}" if cvss not in ("—", "N/A", "") else ""
            print(f"  {tick}  Stage{stage}  {vuln}  [{sev}]{cvss_str}  {elapsed}s  CVE×{len(cves)}\n")

        results.append({
            **case,
            "response":    final,
            "stage":       stage,
            "cvss":        cvss,
            "cve_count":   len(cves),
            "elapsed":     elapsed,
            "detected":    ok,
        })

    # 집계
    total     = len(results)
    n_det     = sum(1 for r in results if r["detected"])
    n_stage1  = sum(1 for r in results if r["stage"] == 1)
    n_stage2  = sum(1 for r in results if r["stage"] == 2)
    avg_t     = round(sum(r["elapsed"] for r in results) / total, 2)
    det_pct   = round(n_det / total * 100, 1)

    if verbose:
        print("─" * 65)
        print(f"탐지율: {n_det}/{total} ({det_pct}%)")
        print(f"평균 응답: {avg_t}s  |  Stage1: {n_stage1}건  Stage2: {n_stage2}건")

    summary = {
        "model_name": name,
        "model_ft":   MODEL_V4,
        "total":      total,
        "detected":   n_det,
        "detect_pct": det_pct,
        "avg_time":   avg_t,
        "stage1_count": n_stage1,
        "stage2_count": n_stage2,
        "results":    results,
    }

    REPORTS.mkdir(exist_ok=True)
    out = REPORTS / "results_ScanOps_v4_QLoRAplusRAG_Adaptive.json"
    out.write_text(json.dumps(summary, ensure_ascii=False, indent=2), encoding="utf-8")
    if verbose:
        print(f"저장: {out}")

    return summary


def compare_versions(v2: dict | None, v3: dict | None, v4: dict) -> None:
    """v2 / v3 / v4 비교 출력."""
    print(f"\n{'='*65}")
    print("  v2 vs v3 vs v4 비교")
    print(f"{'='*65}")

    rows = [
        ("탐지 케이스 (40개 기준)",
         v2["detected"] if v2 else "N/A",
         v3["detected"] if v3 else "N/A",
         v4["detected"]),
        ("탐지율 (%)",
         v2["detect_pct"] if v2 else "N/A",
         v3["detect_pct"] if v3 else "N/A",
         v4["detect_pct"]),
        ("평균 응답 시간 (s)",
         v2["avg_time"] if v2 else "N/A",
         v3["avg_time"] if v3 else "N/A",
         v4["avg_time"]),
        ("Stage1 성공",
         v2.get("stage1_count", "N/A") if v2 else "N/A",
         v3.get("stage1_count", "N/A") if v3 else "N/A",
         v4["stage1_count"]),
    ]

    print(f"{'항목':<35} {'v2':>8} {'v3':>8} {'v4':>8} {'v3→v4':>8}")
    print("─" * 65)
    for label, v2v, v3v, v4v in rows:
        try:
            change = f"{v4v - v3v:+.1f}" if v3 and isinstance(v3v, (int, float)) else "N/A"
        except Exception:
            change = "N/A"
        print(f"  {label:<33} {str(v2v):>8} {str(v3v):>8} {str(v4v):>8} {change:>8}")

    # 케이스별 변화 (v3 → v4)
    if v3 and v3.get("results"):
        v3_map = {r["id"]: r["detected"] for r in v3["results"]}
        v4_map = {r["id"]: r["detected"] for r in v4["results"]}
        changes = []
        for case_id, v4_det in v4_map.items():
            v3_det = v3_map.get(case_id)
            if v3_det is not None and v3_det != v4_det:
                tag = "✗ → ✓" if v4_det else "✓ → ✗"
                # case name lookup
                case = next((c for c in CASES if c["id"] == case_id), None)
                name = f"{case['language']} / {case['expected_vuln']}" if case else str(case_id)
                changes.append(f"  [{case_id:02d}] {name}: {tag}")
        if changes:
            print("\n케이스별 변화 (v3 → v4):")
            for c in changes:
                print(c)
        else:
            print("\n  v3 → v4 케이스별 변화 없음")


def load_prev(path: Path) -> dict | None:
    if path.exists():
        try:
            return json.loads(path.read_text(encoding="utf-8"))
        except Exception:
            pass
    return None


def main() -> None:
    v4 = run_scanops_v4(verbose=True)
    v2 = load_prev(V2_RESULTS_PATH)
    v3 = load_prev(V3_RESULTS_PATH)
    compare_versions(v2, v3, v4)

    # 취약점 유형별 분석
    print(f"\n{'='*65}")
    print("  취약점 유형별 탐지율")
    print(f"{'='*65}")

    from collections import defaultdict
    by_vuln: dict[str, list[bool]] = defaultdict(list)
    for r in v4["results"]:
        key = r.get("expected_vuln", "Unknown")
        by_vuln[key].append(r["detected"])

    for vuln, dets in sorted(by_vuln.items()):
        n = len(dets)
        k = sum(dets)
        bar = "█" * k + "░" * (n - k)
        print(f"  {vuln:<45} {bar}  {k}/{n}")

    print(f"\n  전체 탐지율: {v4['detect_pct']}%  ({v4['detected']}/{v4['total']})")


if __name__ == "__main__":
    main()
