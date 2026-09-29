"""
OWASP Benchmark — 실제 프로덕션 파이프라인(QLoRA FT + RAG 폴백) 성능 테스트
================================================================================
scripts/benchmark_owasp.py는 benchmark_v5.py의 "정적 mitigation + 파인튜닝
안 된 base 모델 1회 호출" 간소화 게이트를 썼는데, 이건 우리가 만든 합성
한 줄짜리 스니펫에만 맞춰 튜닝된 방식이라 OWASP의 실제 50~80줄 서블릿
코드에서 오탐률 92.7%로 무너졌다(정확도 50.9%, 거의 동전던지기).

이 스크립트는 실제 운영 중인 scripts/api_server.py::run_adaptive()와
동일한 로직 — ① QLoRA로 파인튜닝한 모델(qwen2.5-coder-security-v4)이
RAG 없이 1차 탐지 → ② 유효성 검증 실패 시에만 base 모델 + Qdrant RAG로
2차 폴백 — 을 그대로 재현해 같은 110케이스를 다시 돌린다. 추가로 다음을
분리 측정해 "QLoRA 파인튜닝이 실제로 도움이 되는지"를 직접 확인한다:

  ① ScanOps Stage1 단독 (QLoRA FT, RAG 없음) — 파인튜닝 자체의 순수 효과
  ② ScanOps 전체 어댑티브 (Stage1 실패 시 Stage2 RAG 폴백) — 실제 프로덕션 동작
  ③ Grok-3-mini, ①과 완전히 동일한 프롬프트·파싱·판정 기준 (LLM 코어만 교체)

실행:
  source .venv/bin/activate
  python scripts/benchmark_owasp_adaptive.py
"""
from __future__ import annotations

import json
import sys
import time
from datetime import datetime
from pathlib import Path

BASE = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(BASE))
sys.path.insert(0, str(BASE / "scripts"))

from scripts.benchmark_qwen_rag import (
    build_ft_user_prompt,
    build_base_rag_prompt,
    call_model,
    parse_response,
    search_cves,
)
from scripts.benchmark_v5 import score
from scripts.owasp_benchmark_cases import build_cases
from scripts.grok_client import query_llm

REPORTS = BASE / "reports"

# 실제 프로덕션(scripts/api_server.py)과 동일한 모델 — v4가 최신 배포 모델
MODEL_FT = "qwen2.5-coder-security-v4:latest"
MODEL_BASE = "qwen2.5-coder:1.5b"

# api_server.py::_is_valid_vuln / _VULN_GARBAGE 와 동일 (헛것 필터)
_VULN_GARBAGE = (
    "vulnerability:", "last line", "at end of", "at the end", "on line ",
    "in the code", "in the function", "the vulnerability is", "this vulnerability",
)


def _is_valid_vuln(text: str) -> bool:
    if not text or text in ("—", "N/A", ""):
        return False
    t = text.lower()
    if any(p in t for p in _VULN_GARBAGE):
        return False
    if text.count(". ") >= 2:
        return False
    return True


def _ok(vuln: str, sev: str) -> bool:
    return _is_valid_vuln(vuln) and sev not in ("—", "N/A", "", None)


# ── ① ScanOps Stage1 단독 (QLoRA FT, RAG 없음) ──────────────────────────────
def judge_scanops_stage1(case: dict) -> dict:
    t0 = time.time()
    try:
        content = build_ft_user_prompt(case["language"], case["code"])
        raw, _ = call_model(content, MODEL_FT, is_finetuned=True, timeout=60)
        parsed = parse_response(raw)
    except Exception as e:
        raw, parsed = f"ERROR: {e}", {}
    vuln = parsed.get("VULNERABILITY", "—")
    sev = parsed.get("SEVERITY", "—")
    flagged = _ok(vuln, sev)
    return {"flagged": flagged, "cwe": vuln[:60], "elapsed": round(time.time() - t0, 2),
            "raw": raw[:150], "stage": 1}


# ── ② ScanOps 전체 어댑티브 (Stage1 실패 시 Stage2 RAG 폴백) — 실제 운영 로직 ──
def judge_scanops_adaptive(case: dict) -> dict:
    t0 = time.time()
    try:
        content_ft = build_ft_user_prompt(case["language"], case["code"])
        raw_ft, _ = call_model(content_ft, MODEL_FT, is_finetuned=True, timeout=60)
        parsed_ft = parse_response(raw_ft)
    except Exception:
        raw_ft, parsed_ft = "", {}

    vuln_ft = parsed_ft.get("VULNERABILITY", "—")
    sev_ft = parsed_ft.get("SEVERITY", "—")
    stage = 1
    final = parsed_ft
    raw_final = raw_ft

    if not _ok(vuln_ft, sev_ft):
        stage = 2
        hint = vuln_ft if vuln_ft not in ("—", "N/A", "", None) else "security vulnerability"
        cve_q = f"{case['language']} {hint} {case['code'][:120]}"
        try:
            cves = search_cves(cve_q)
        except Exception:
            cves = []
        try:
            content_b = build_base_rag_prompt(case["language"], case["code"], cves)
            raw_b, _ = call_model(content_b, MODEL_BASE, is_finetuned=False, timeout=90)
            final = parse_response(raw_b)
            raw_final = raw_b
        except Exception:
            pass

    vuln = final.get("VULNERABILITY", "—")
    flagged = vuln not in ("—", "N/A", "", None)
    return {"flagged": flagged, "cwe": vuln[:60], "elapsed": round(time.time() - t0, 2),
            "raw": raw_final[:150], "stage": stage}


# ── ③ Grok-3-mini — ①과 완전히 동일한 프롬프트·파싱·판정 기준 ────────────────
def judge_grok_same_format(case: dict) -> dict:
    t0 = time.time()
    content = build_ft_user_prompt(case["language"], case["code"])
    try:
        raw, _ = query_llm(
            prompt=content,
            system_prompt="You are a precise security code analyzer. Follow the requested output format exactly.",
            model="grok-3-mini",
            temperature=0.0,
            max_tokens=400,
        )
    except Exception as e:
        raw = f"ERROR: {e}"
    parsed = parse_response(raw)
    vuln = parsed.get("VULNERABILITY", "—")
    sev = parsed.get("SEVERITY", "—")
    flagged = _ok(vuln, sev)
    return {"flagged": flagged, "cwe": vuln[:60], "elapsed": round(time.time() - t0, 2), "raw": raw[:150]}


def run_system(name: str, judge_fn, cases: list[dict], verbose=True) -> dict:
    if verbose:
        print(f"\n{'='*70}\n  {name}\n{'='*70}")
    results = []
    for c in cases:
        try:
            j = judge_fn(c)
        except Exception as e:
            j = {"flagged": False, "cwe": "ERR", "elapsed": 0.0, "raw": str(e)[:80]}
        row = {"id": c["id"], "label": c["label"], "language": c["language"],
               "category": c["category"], "expected_vuln": c["expected_vuln"], **j}
        results.append(row)
        if verbose:
            truth = "VULN" if c["label"] == "vuln" else "SAFE"
            pred = "VULN" if j["flagged"] else "SAFE"
            ok = "OK" if pred == truth else "XX"
            print(f"  [{c['id']}] {ok} truth={truth} pred={pred:4} {c['category']:12} {j.get('elapsed',0):>5.2f}s")
    s = score(results)
    if verbose:
        print(f"  → 탐지율(recall) {s['detection_recall']}%  오탐률(FPR) {s['false_positive_rate']}%  "
              f"정밀도 {s['precision']}%  정확도 {s['accuracy']}%  F1 {s['f1']}  avg {s['avg_time']}s")
    return {"model_name": name, "metrics": s, "results": results}


def by_category(results: list[dict], cases: list[dict]) -> dict:
    cat_of = {c["id"]: c["category"] for c in cases}
    out: dict[str, dict] = {}
    for r in results:
        cat = cat_of.get(r["id"], "?")
        b = out.setdefault(cat, {"n": 0, "correct": 0})
        b["n"] += 1
        expected = r["label"] == "vuln"
        b["correct"] += int(r["flagged"] == expected)
    return {k: {"n": v["n"], "accuracy": round(100 * v["correct"] / v["n"], 1)} for k, v in out.items()}


def main():
    cases = build_cases()
    if not cases:
        print("OWASP Benchmark 샘플이 없습니다. 먼저 owasp_benchmark_cases.py를 실행하세요.")
        return

    print(f"OWASP Benchmark — 프로덕션 파이프라인 비교, {len(cases)}케이스 "
          f"(취약 {sum(1 for c in cases if c['label']=='vuln')} / "
          f"안전 {sum(1 for c in cases if c['label']=='safe')})")

    stage1 = run_system("① ScanOps Stage1 단독 (QLoRA FT, RAG 없음)", judge_scanops_stage1, cases)
    adaptive = run_system("② ScanOps 전체 어댑티브 (Stage1+Stage2 RAG 폴백, 실제 운영 로직)", judge_scanops_adaptive, cases)
    grok = run_system("③ Grok-3-mini (동일 프롬프트·파싱 기준)", judge_grok_same_format, cases)

    print("\n" + "=" * 70)
    print("종합 비교")
    for name, r in [("① Stage1 단독", stage1), ("② 전체 어댑티브", adaptive), ("③ Grok-3-mini", grok)]:
        m = r["metrics"]
        print(f"  {name:16} 정확도={m['accuracy']:5.1f}%  탐지율={m['detection_recall']:5.1f}%  "
              f"오탐률={m['false_positive_rate']:5.1f}%  avg={m['avg_time']}s")
    print("=" * 70)

    print("\n카테고리별 정확도:")
    cats = sorted(by_category(stage1["results"], cases))
    bc_s1, bc_ad, bc_gk = by_category(stage1["results"], cases), by_category(adaptive["results"], cases), by_category(grok["results"], cases)
    for cat in cats:
        print(f"  {cat:14} n={bc_s1[cat]['n']:3}  Stage1={bc_s1[cat]['accuracy']:5.1f}%  "
              f"어댑티브={bc_ad[cat]['accuracy']:5.1f}%  Grok={bc_gk[cat]['accuracy']:5.1f}%")

    summary = {
        "generated": datetime.now().isoformat(timespec="seconds"),
        "source": "OWASP Benchmark v1.2 (external, https://github.com/OWASP-Benchmark/BenchmarkJava)",
        "n_cases": len(cases),
        "systems": [stage1, adaptive, grok],
        "category_breakdown": {"stage1": bc_s1, "adaptive": bc_ad, "grok": bc_gk},
    }
    REPORTS.mkdir(exist_ok=True)
    out = REPORTS / "results_owasp_adaptive_benchmark.json"
    out.write_text(json.dumps(summary, indent=2, ensure_ascii=False), encoding="utf-8")
    print(f"\n저장: {out}")


if __name__ == "__main__":
    main()
