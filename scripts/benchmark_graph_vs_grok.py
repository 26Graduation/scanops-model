"""
ScanOps 코드 그래프(Neo4j) vs Grok 비교 벤치마크 (100케이스)
================================================================
v5 벤치마크(scripts/benchmark_v5.py)는 "최신 2026 NVD CVE 패턴을 더 빠르고
비슷한 정확도로 잡는다"는 것을 보여준다. 이 스크립트는 v5가 다루지 않는 부분,
즉 "코드 그래프(Neo4j) 기반 멀티파일 데이터 흐름 추적"이라는 *아키텍처 차이*를
대규모(100케이스)로 비교한다.

케이스 구성 (scripts/graph_benchmark_cases.py):
  - GROUP A "cve_2026" 50개 — 2026년 5~6월 NVD에 실제 공개된 XSS(CWE-79)/
    SSRF(CWE-918) CVE 25개씩을 출처로, "사용자 입력이 sink까지 도달하는 취약
    버전"과 "정적 자원/안전 격리라 무관한 버전"을 절반씩 재구성.
  - GROUP B "structural" 50개 — sink 종류(img/innerHTML/dangerouslySetInnerHTML/
    fetch/axios.*) × prop-hop 깊이(0~2) × 별칭(alias) 체인 여부를 조합해
    그래프 추적 로직 자체의 견고성을 검증.

비교 대상:
  - ScanOps: scanops/core/code_graph.py 의 그래프 엔진이 직접 산출하는 verdict
    (tainted=취약 유지, safe=정적 import로 추적되어 무관) — API 서버
    (_enrich_with_graph)가 실제로 사용하는 것과 동일한 evidence_for_finding()
    함수를 그대로 호출한다. (1차 LLM 탐지 단계는 카테고리만 일치하면 그래프
    판정 결과에 영향이 없으므로, 대규모 비교에서는 그래프 엔진 자체를 직접
    검증해 Ollama 호출 비용 없이 정확히 같은 결론을 얻는다. 1차 LLM 탐지
    자체의 탐지율은 scripts/benchmark_v5.py 의 100케이스로 별도 검증됨.)
  - Grok-3-mini: 동일한 멀티파일 코드를 그래프 없이 텍스트로만 보고
    VULNERABLE/SAFE를 판정.

실행:
  source .venv/bin/activate
  python scripts/benchmark_graph_vs_grok.py
"""
from __future__ import annotations

import json
import sys
import time
from concurrent.futures import ThreadPoolExecutor, as_completed
from datetime import datetime, timezone
from pathlib import Path

BASE = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(BASE))
sys.path.insert(0, str(BASE / "scripts"))

from scanops.core.code_graph import CodeFile, build_code_graph, evidence_for_finding
from scripts.graph_benchmark_cases import CASES
from scripts.grok_client import query_llm

REPORTS = BASE / "reports"
GROK_WORKERS = 6

VULN_LABEL = {
    "xss": "Cross-Site Scripting (XSS)",
    "ssrf": "Server-Side Request Forgery (SSRF)",
}
CATEGORY_LABEL = {
    "xss": "XSS (Cross-Site Scripting)",
    "ssrf": "SSRF (Server-Side Request Forgery)",
}

GROK_GRAPH_PROMPT = """You are a strict application-security auditor reviewing a small multi-file
React/JS codebase. Decide whether the TARGET FILE has a real, exploitable
{category_label} vulnerability, considering how data flows across the files shown.

Reply with only one line:
VERDICT: VULNERABLE
or
VERDICT: SAFE

Files:
{files_block}

Target file: {target_file}
Verdict:"""


def _files_block(files: dict[str, str]) -> str:
    return "\n\n".join(f"--- {name} ---\n```\n{content}```" for name, content in files.items())


def run_scanops_graph(case: dict) -> dict:
    """scanops/core/code_graph.py 의 그래프 엔진이 직접 산출하는 판정.
    API 서버의 _enrich_with_graph가 호출하는 evidence_for_finding()과 동일.
    """
    t0 = time.time()
    code_files = [CodeFile(filename=n, language="tsx", content=c) for n, c in case["files"].items()]
    graph = build_code_graph(code_files)
    evidence = evidence_for_finding(graph, case["target_file"], VULN_LABEL[case["category"]])

    has_tainted = any(e.verdict == "tainted" for e in evidence)
    has_safe = any(e.verdict == "safe" for e in evidence)
    if has_tainted:
        vulnerable = True
    elif has_safe:
        vulnerable = False
    else:
        vulnerable = None  # 그래프가 판단 못한 경우(이 케이스셋엔 없어야 함)

    elapsed = round(time.time() - t0, 4)
    return {
        "vulnerable": vulnerable,
        "verdicts": [e.verdict for e in evidence],
        "elapsed": elapsed,
    }


def run_grok_graph(case: dict) -> dict:
    label = CATEGORY_LABEL[case["category"]]
    prompt = GROK_GRAPH_PROMPT.format(
        category_label=label,
        files_block=_files_block(case["files"]),
        target_file=case["target_file"],
    )
    t0 = time.time()
    try:
        raw, _ = query_llm(
            prompt=prompt,
            system_prompt="You are a precise application-security code auditor. Avoid false alarms.",
            model="grok-3-mini",
            temperature=0.0,
            max_tokens=20,
        )
    except Exception as e:
        raw = f"ERROR: {e}"
    elapsed = round(time.time() - t0, 2)
    vulnerable = "VULNERAB" in raw.upper()
    return {"vulnerable": vulnerable, "raw": raw.strip(), "elapsed": elapsed}


def main():
    n = len(CASES)
    print("=" * 70)
    print(f"ScanOps 코드 그래프(Neo4j) vs Grok — {n}케이스 비교")
    print("=" * 70)

    scanops_results = {c["id"]: run_scanops_graph(c) for c in CASES}
    print(f"[ScanOps 그래프 엔진] {n}케이스 판정 완료 (인메모리, 거의 즉시)")

    grok_results: dict[str, dict] = {}
    print(f"[Grok-3-mini] {n}케이스 질의 중 (동시 {GROK_WORKERS}개)...")
    with ThreadPoolExecutor(max_workers=GROK_WORKERS) as pool:
        futures = {pool.submit(run_grok_graph, c): c["id"] for c in CASES}
        done = 0
        for fut in as_completed(futures):
            cid = futures[fut]
            grok_results[cid] = fut.result()
            done += 1
            if done % 10 == 0 or done == n:
                print(f"  ... {done}/{n}")

    rows = []
    so_correct = gk_correct = 0
    so_time = gk_time = 0.0
    breakdown = {}

    for case in CASES:
        so = scanops_results[case["id"]]
        gk = grok_results[case["id"]]
        so_ok = so["vulnerable"] == case["expected_vulnerable"]
        gk_ok = gk["vulnerable"] == case["expected_vulnerable"]
        so_correct += so_ok
        gk_correct += gk_ok
        so_time += so["elapsed"]
        gk_time += gk["elapsed"]

        group = "cve_2026" if case["id"].startswith("cve26") else "structural"
        b = breakdown.setdefault(group, {"n": 0, "so": 0, "gk": 0})
        b["n"] += 1
        b["so"] += so_ok
        b["gk"] += gk_ok

        rows.append({
            "id": case["id"], "title": case["title"], "category": case["category"],
            "cve": case.get("cve"), "hop": case["hop"], "alias": case["alias"],
            "expected_vulnerable": case["expected_vulnerable"],
            "scanops": {**so, "correct": so_ok},
            "grok": {**gk, "correct": gk_ok},
        })

    summary = {
        "generated": datetime.now(timezone.utc).isoformat(),
        "n_cases": n,
        "scanops_accuracy": round(100 * so_correct / n, 1),
        "grok_accuracy": round(100 * gk_correct / n, 1),
        "scanops_avg_time": round(so_time / n, 4),
        "grok_avg_time": round(gk_time / n, 3),
        "breakdown": {
            g: {
                "n": v["n"],
                "scanops_accuracy": round(100 * v["so"] / v["n"], 1),
                "grok_accuracy": round(100 * v["gk"] / v["n"], 1),
            }
            for g, v in breakdown.items()
        },
        "cases": rows,
    }

    print("\n" + "=" * 70)
    print(f"전체 {n}케이스")
    print(f"  ScanOps 정확도: {summary['scanops_accuracy']}%  (avg {summary['scanops_avg_time']}s)")
    print(f"  Grok 정확도   : {summary['grok_accuracy']}%  (avg {summary['grok_avg_time']}s)")
    for g, v in summary["breakdown"].items():
        print(f"  [{g}] n={v['n']}  ScanOps={v['scanops_accuracy']}%  Grok={v['grok_accuracy']}%")
    print("=" * 70)

    # 오답 케이스 요약 출력
    grok_wrong = [r for r in rows if not r["grok"]["correct"]]
    so_wrong = [r for r in rows if not r["scanops"]["correct"]]
    print(f"\nGrok 오답 {len(grok_wrong)}개 (예시 5개):")
    for r in grok_wrong[:5]:
        print(f"  - [{r['id']}] 정답={r['expected_vulnerable']} Grok판정={r['grok']['vulnerable']} ({r['title'][:50]})")
    if so_wrong:
        print(f"\nScanOps 오답 {len(so_wrong)}개:")
        for r in so_wrong[:5]:
            print(f"  - [{r['id']}] 정답={r['expected_vulnerable']} ScanOps판정={r['scanops']['vulnerable']}")

    REPORTS.mkdir(exist_ok=True)
    out = REPORTS / "results_graph_vs_grok.json"
    out.write_text(json.dumps(summary, indent=2, ensure_ascii=False), encoding="utf-8")
    print(f"\n저장: {out}")


if __name__ == "__main__":
    main()
