"""
OWASP Benchmark(외부 표준 데이터셋) 기반 ScanOps vs Grok 비교
================================================================
scripts/benchmark_v5.py 의 하이브리드 판정 파이프라인(정적 mitigation
분석 → SAFE 보정, 아니면 소형 LLM 어댑저케이션)을 그대로 재사용하되,
우리가 만든 합성 케이스가 아니라 OWASP Benchmark(Java, 외부 표준
SAST 평가 데이터셋)에서 카테고리별로 균등 샘플링한 110케이스로 비교한다.
LLM 코어만 교체(ScanOps: qwen2.5-coder:1.5b / Grok: grok-3-mini)해 공정 비교.

사전 준비:
  git clone https://github.com/OWASP-Benchmark/BenchmarkJava.git \
    scanops-model/.cache/owasp-benchmark
  python scripts/owasp_benchmark_cases.py   # 샘플 110개 생성

실행:
  source .venv/bin/activate
  python scripts/benchmark_owasp.py
"""
from __future__ import annotations

import json
import sys
from datetime import datetime
from pathlib import Path

BASE = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(BASE))
sys.path.insert(0, str(BASE / "scripts"))

import scripts.benchmark_v5 as v5
from scripts.owasp_benchmark_cases import build_cases

REPORTS = BASE / "reports"


def run_system(name: str, judge_fn, cases: list[dict], verbose=True) -> dict:
    """benchmark_v5.run_system과 동일하지만, OWASP의 문자열 id(BenchmarkTestNNNNN)에
    맞춰 출력 포맷만 수정."""
    if verbose:
        print(f"\n{'='*70}\n  {name}\n{'='*70}")
    results = []
    for c in cases:
        try:
            j = judge_fn(c)
        except Exception as e:
            j = {"flagged": False, "cwe": "ERR", "elapsed": 0.0, "raw": str(e)[:80]}
        row = {"id": c["id"], "label": c["label"], "language": c["language"],
               "cwe": c.get("cwe", "-"), "expected_vuln": c["expected_vuln"], **j}
        results.append(row)
        if verbose:
            truth = "VULN" if c["label"] == "vuln" else "SAFE"
            pred = "VULN" if j["flagged"] else "SAFE"
            ok = "OK" if pred == truth else "XX"
            print(f"  [{c['id']}] {ok} truth={truth} pred={pred:4} {c['expected_vuln'][:30]}")
    s = v5.score(results)
    if verbose:
        print(f"  → 탐지율(recall) {s['detection_recall']}%  오탐률(FPR) {s['false_positive_rate']}%  "
              f"정밀도 {s['precision']}%  정확도 {s['accuracy']}%  F1 {s['f1']}  avg {s['avg_time']}s")
    return {"model_name": name, "metrics": s, "results": results}


def main():
    cases = build_cases()
    if not cases:
        print("OWASP Benchmark 샘플이 없습니다. 먼저 owasp_benchmark_cases.py를 실행하세요.")
        return

    print(f"OWASP Benchmark 외부 표준 데이터셋 — {len(cases)}케이스 "
          f"(취약 {sum(1 for c in cases if c['label']=='vuln')} / "
          f"안전 {sum(1 for c in cases if c['label']=='safe')}, 11개 카테고리)")

    sv5 = run_system("ScanOps (FT detect + adjudication gate) — OWASP", v5.judge_scanops_v5, cases)
    grok = run_system("Grok-3-mini (xAI) — OWASP", v5.judge_grok, cases)

    # 카테고리별 breakdown
    def by_category(results: list[dict]) -> dict:
        cat_of = {c["id"]: c["category"] for c in cases}
        out: dict[str, dict] = {}
        for r in results:
            cat = cat_of.get(r["id"], "?")
            b = out.setdefault(cat, {"n": 0, "correct": 0})
            b["n"] += 1
            expected = r["label"] == "vuln"
            b["correct"] += int(r["flagged"] == expected)
        return {k: {"n": v["n"], "accuracy": round(100 * v["correct"] / v["n"], 1)} for k, v in out.items()}

    summary = {
        "generated": datetime.now().isoformat(timespec="seconds"),
        "source": "OWASP Benchmark v1.2 (https://github.com/OWASP-Benchmark/BenchmarkJava)",
        "n_cases": len(cases),
        "n_vuln": sum(1 for c in cases if c["label"] == "vuln"),
        "n_safe": sum(1 for c in cases if c["label"] == "safe"),
        "systems": [sv5, grok],
        "category_breakdown": {
            "scanops": by_category(sv5["results"]),
            "grok": by_category(grok["results"]),
        },
    }

    print("\n" + "=" * 70)
    print(f"ScanOps : {sv5['metrics']}")
    print(f"Grok-3  : {grok['metrics']}")
    print("=" * 70)
    print("\n카테고리별 정확도:")
    for cat in sorted(summary["category_breakdown"]["scanops"]):
        so = summary["category_breakdown"]["scanops"][cat]
        gk = summary["category_breakdown"]["grok"][cat]
        print(f"  {cat:14} n={so['n']:3}  ScanOps={so['accuracy']:5.1f}%  Grok={gk['accuracy']:5.1f}%")

    REPORTS.mkdir(exist_ok=True)
    out = REPORTS / "results_owasp_benchmark.json"
    out.write_text(json.dumps(summary, indent=2, ensure_ascii=False), encoding="utf-8")
    print(f"\n저장: {out}")


if __name__ == "__main__":
    main()
