"""
OWASP Benchmark — OUTPUT_FORMAT에 'SAFE 탈출구' 추가 후 재검증
================================================================
benchmark_owasp_adaptive.py 결과: ScanOps Stage1/어댑티브뿐 아니라
Grok-3-mini까지 동일 프롬프트(build_ft_user_prompt)로는 정확도 49~51%
(오탐률 98~100%)로 무너졌다. 원인은 모델이 아니라
scripts/benchmark_qwen_rag.py::OUTPUT_FORMAT 프롬프트 — "List ALL
security vulnerabilities found"라고만 시키고 "없으면 SAFE"라는 탈출구가
전혀 없다. 이건 scripts/api_server.py::run_adaptive() Stage1이 실제로
쓰는 프로덕션 프롬프트와 동일하다 — 즉 프로덕션 코드 자체의 결함이다.

이 스크립트는 OUTPUT_FORMAT에 명시적 SAFE 분기를 추가한 수정 버전으로
같은 110케이스를 다시 돌려, 오탐률이 실제로 줄어드는지 검증한다.

실행:
  source .venv/bin/activate
  python scripts/benchmark_owasp_fixed_prompt.py
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

from scripts.benchmark_qwen_rag import call_model, parse_response, _lang_hint
from scripts.benchmark_owasp_adaptive import judge_grok_same_format  # noqa (참고용, 직접 호출 안 함)
from scripts.benchmark_v5 import score
from scripts.owasp_benchmark_cases import build_cases
from scripts.grok_client import query_llm

REPORTS = BASE / "reports"
MODEL_FT = "qwen2.5-coder-security-v4:latest"

# ── 수정된 OUTPUT_FORMAT: 명시적 SAFE 탈출구 추가 ────────────────────────────
FIXED_OUTPUT_FORMAT = """\
First decide whether the code has a REAL, exploitable security vulnerability.

If the code is SAFE (no real vulnerability — e.g. parameterized queries, \
output escaping, input validation, strong crypto/hash, secure randomness, \
proper auth checks already present), respond with EXACTLY one line:
VULNERABILITY: NONE

If the code DOES have a real vulnerability, list ALL of them. For EACH \
vulnerability, use EXACTLY this format, separated by ---:
VULNERABILITY: [vulnerability name with CWE ID]
SEVERITY: [CRITICAL/HIGH/MEDIUM/LOW]
CVSS: [CVSS base score, e.g. 9.8]
ATTACK: [한 문장으로 공격 시나리오 설명 (반드시 한국어)]
FIX: [수정된 코드. 코드가 없으면 한국어로 해결 방법 설명]
---"""


def build_fixed_prompt(language: str, code: str) -> str:
    hint = _lang_hint(language)
    return (
        f"Analyze this {language} code for security vulnerabilities:\n\n"
        f"```{hint}\n{code}\n```\n\n"
        f"{FIXED_OUTPUT_FORMAT}"
    )


def _flagged(vuln: str) -> bool:
    if not vuln or vuln in ("—", "N/A", ""):
        return False
    return vuln.strip().upper() != "NONE"


def judge_scanops_fixed(case: dict) -> dict:
    t0 = time.time()
    try:
        content = build_fixed_prompt(case["language"], case["code"])
        raw, _ = call_model(content, MODEL_FT, is_finetuned=True, timeout=60)
        parsed = parse_response(raw)
    except Exception as e:
        raw, parsed = f"ERROR: {e}", {}
    vuln = parsed.get("VULNERABILITY", "—")
    flagged = _flagged(vuln)
    return {"flagged": flagged, "cwe": vuln[:60], "elapsed": round(time.time() - t0, 2), "raw": raw[:150]}


def judge_grok_fixed(case: dict) -> dict:
    t0 = time.time()
    content = build_fixed_prompt(case["language"], case["code"])
    try:
        raw, _ = query_llm(
            prompt=content,
            system_prompt="You are a precise security code analyzer. Avoid false alarms on safe code.",
            model="grok-3-mini",
            temperature=0.0,
            max_tokens=400,
        )
    except Exception as e:
        raw = f"ERROR: {e}"
    parsed = parse_response(raw)
    vuln = parsed.get("VULNERABILITY", "—")
    flagged = _flagged(vuln)
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


def main():
    cases = build_cases()
    print(f"OWASP Benchmark — SAFE 탈출구 추가 프롬프트 검증, {len(cases)}케이스")

    so = run_system("ScanOps (FT v4, SAFE 탈출구 추가 프롬프트)", judge_scanops_fixed, cases)
    gk = run_system("Grok-3-mini (동일 수정 프롬프트)", judge_grok_fixed, cases)

    print("\n" + "=" * 70)
    print("수정 전/후 비교")
    print(f"  ScanOps  수정전: 정확도 49.1% 오탐 100.0%  →  수정후: 정확도 {so['metrics']['accuracy']}% 오탐 {so['metrics']['false_positive_rate']}%")
    print(f"  Grok-3   수정전: 정확도 50.9% 오탐  98.2%  →  수정후: 정확도 {gk['metrics']['accuracy']}% 오탐 {gk['metrics']['false_positive_rate']}%")
    print("=" * 70)

    summary = {
        "generated": datetime.now().isoformat(timespec="seconds"),
        "note": "OUTPUT_FORMAT에 명시적 SAFE 탈출구를 추가한 수정 프롬프트로 OWASP 110케이스 재검증",
        "n_cases": len(cases),
        "systems": [so, gk],
    }
    REPORTS.mkdir(exist_ok=True)
    out = REPORTS / "results_owasp_fixed_prompt_benchmark.json"
    out.write_text(json.dumps(summary, indent=2, ensure_ascii=False), encoding="utf-8")
    print(f"\n저장: {out}")


if __name__ == "__main__":
    main()
