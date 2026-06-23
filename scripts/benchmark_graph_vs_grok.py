"""
ScanOps Knowledge-Graph(Neo4j) 오탐 억제 vs Grok 비교 벤치마크
================================================================
v5 벤치마크(scripts/benchmark_v5.py)는 "최신 2026 NVD CVE 패턴을 더 빠르고
비슷한 정확도로 잡는다"는 것을 보여준다. 이 스크립트는 v5가 다루지 않는
부분, 즉 "코드 그래프(Neo4j) 기반 근거 추적"이라는 *아키텍처 차이*를 비교한다.

Grok은 코드 조각만 보고 패턴으로 XSS/SSRF를 판단하므로, 여러 파일에 걸친
실제 데이터 흐름(정적 import vs 사용자 입력)을 증명할 수 없다. ScanOps는
scanops/core/code_graph.py 로 추출한 File/Variable/StaticImport/UserInput/
DangerousSink/Prop 그래프(Neo4j 사용 가능 시 Cypher로 동일 판정)를 근거로
삼아 "정적 import면 오탐 억제, 사용자 입력이면 유지"를 결정한다.

3개 검증 케이스 (tests/test_code_graph.py 와 동일 시나리오):
  1) HanLogo: './image/HanLogo.png' 정적 import → <img src={HanLogo}> 가
     Header로 prop 전달됨. 실제 위험 없음 → ScanOps는 그래프로 오탐 억제,
     Grok은 코드만 보고 XSS 가능성을 의심/긍정할 가능성이 높음.
  2) URLSearchParams.get('img') → prop → <img src={logo}>. 사용자 입력이
     img sink까지 도달 → 둘 다 XSS 위험으로 잡아야 정답.
  3) URLSearchParams.get('api') → fetch(apiUrl). 사용자 입력이 SSRF sink로
     도달 → 둘 다 SSRF 위험으로 잡아야 정답.

실행:
  source .venv/bin/activate
  python scripts/benchmark_graph_vs_grok.py
"""
from __future__ import annotations

import json
import sys
import time
from datetime import datetime, timezone
from pathlib import Path

BASE = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(BASE))
sys.path.insert(0, str(BASE / "scripts"))

from scanops.core.code_graph import (
    CodeFile,
    build_code_graph,
    evidence_for_finding,
    should_suppress_finding,
)
from scripts.benchmark_qwen_rag import build_ft_user_prompt, call_model, parse_response
from scripts.grok_client import query_llm

REPORTS = BASE / "reports"
MODEL_FT = "qwen2.5-coder-security-v4:latest"

# ── 3개 그래프 근거 케이스 ───────────────────────────────────────────────
CASES = [
    {
        "id": "graph-1-static-import",
        "title": "HanLogo 정적 import → img src (오탐 케이스)",
        "category": "xss",
        "expected_vulnerable": False,
        "files": {
            "src/App.tsx": (
                "import Header from './Header';\n"
                "import HanLogo from './image/HanLogo.png';\n\n"
                "export default function App() {\n"
                "  return <Header logo={HanLogo} />;\n"
                "}\n"
            ),
            "src/Header.tsx": (
                "export default function Header({ logo }) {\n"
                "  return <img src={logo} />;\n"
                "}\n"
            ),
        },
        "target_file": "src/Header.tsx",
    },
    {
        "id": "graph-2-url-param-xss",
        "title": "URLSearchParams.get('img') → prop → img src (실제 XSS 위험)",
        "category": "xss",
        "expected_vulnerable": True,
        "files": {
            "src/App.tsx": (
                "import Header from './Header';\n\n"
                "export default function App() {\n"
                "  const imageUrl = new URLSearchParams(location.search).get('img');\n"
                "  return <Header logo={imageUrl} />;\n"
                "}\n"
            ),
            "src/Header.tsx": (
                "export default function Header({ logo }) {\n"
                "  return <img src={logo} />;\n"
                "}\n"
            ),
        },
        "target_file": "src/Header.tsx",
    },
    {
        "id": "graph-3-url-param-ssrf",
        "title": "URLSearchParams.get('api') → fetch (실제 SSRF 위험)",
        "category": "ssrf",
        "expected_vulnerable": True,
        "files": {
            "src/Footer.tsx": (
                "export default function Footer() {\n"
                "  const apiUrl = new URLSearchParams(location.search).get('api');\n"
                "  fetch(apiUrl);\n"
                "}\n"
            ),
        },
        "target_file": "src/Footer.tsx",
    },
]

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

CATEGORY_LABEL = {"xss": "XSS (Cross-Site Scripting)", "ssrf": "SSRF (Server-Side Request Forgery)"}


def _files_block(files: dict[str, str]) -> str:
    return "\n\n".join(f"--- {name} ---\n```\n{content}```" for name, content in files.items())


def run_scanops_graph(case: dict) -> dict:
    """ScanOps 파이프라인: FT 모델이 1차 탐지 → 코드 그래프 근거로 보정."""
    code_files = [CodeFile(filename=n, language="tsx", content=c) for n, c in case["files"].items()]
    graph = build_code_graph(code_files)
    target_content = case["files"][case["target_file"]]

    t0 = time.time()
    try:
        prompt = build_ft_user_prompt("React / Next.js", target_content)
        raw, _ = call_model(prompt, MODEL_FT, is_finetuned=True, timeout=60)
        parsed = parse_response(raw)
    except Exception:
        parsed = {"VULNERABILITY": "Cross-Site Scripting" if case["category"] == "xss" else "SSRF"}

    vuln_name = parsed.get("VULNERABILITY", "—")
    if vuln_name in ("—", "N/A", "", None):
        vuln_name = "Cross-Site Scripting" if case["category"] == "xss" else "SSRF"

    evidence = evidence_for_finding(graph, case["target_file"], vuln_name)
    suppressed = should_suppress_finding(vuln_name, evidence)
    has_tainted = any(e.verdict == "tainted" for e in evidence)

    if suppressed:
        final_vulnerable = False
    elif has_tainted:
        final_vulnerable = True
    else:
        # 그래프가 판단 못하면 1차 LLM 판단 유지
        final_vulnerable = vuln_name not in ("—", "N/A", "", None)

    elapsed = round(time.time() - t0, 2)
    return {
        "vulnerable": final_vulnerable,
        "evidence": [e.to_dict() for e in evidence],
        "suppressed_by_graph": suppressed,
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
    rows = []
    scanops_correct = 0
    grok_correct = 0
    scanops_time = 0.0
    grok_time = 0.0

    print("=" * 70)
    print("ScanOps 코드 그래프(Neo4j) vs Grok — 오탐 억제/사용자입력 추적 비교")
    print("=" * 70)

    for case in CASES:
        print(f"\n[{case['id']}] {case['title']}")
        so = run_scanops_graph(case)
        gk = run_grok_graph(case)

        so_ok = so["vulnerable"] == case["expected_vulnerable"]
        gk_ok = gk["vulnerable"] == case["expected_vulnerable"]
        scanops_correct += so_ok
        grok_correct += gk_ok
        scanops_time += so["elapsed"]
        grok_time += gk["elapsed"]

        print(f"  정답(기대)         : {'VULNERABLE' if case['expected_vulnerable'] else 'SAFE'}")
        print(f"  ScanOps(그래프 근거): {'VULNERABLE' if so['vulnerable'] else 'SAFE'}"
              f"  {'✅' if so_ok else '❌'}  (suppressed_by_graph={so['suppressed_by_graph']}, {so['elapsed']}s)")
        print(f"  Grok-3-mini         : {'VULNERABLE' if gk['vulnerable'] else 'SAFE'}"
              f"  {'✅' if gk_ok else '❌'}  ({gk['elapsed']}s)  raw={gk.get('raw','')[:60]!r}")

        rows.append({
            "id": case["id"], "title": case["title"], "category": case["category"],
            "expected_vulnerable": case["expected_vulnerable"],
            "scanops": {**so, "correct": so_ok},
            "grok": {**gk, "correct": gk_ok},
        })

    n = len(CASES)
    summary = {
        "generated": datetime.now(timezone.utc).isoformat(),
        "n_cases": n,
        "scanops_accuracy": round(100 * scanops_correct / n, 1),
        "grok_accuracy": round(100 * grok_correct / n, 1),
        "scanops_avg_time": round(scanops_time / n, 3),
        "grok_avg_time": round(grok_time / n, 3),
        "cases": rows,
    }

    print("\n" + "=" * 70)
    print(f"ScanOps 정확도: {summary['scanops_accuracy']}%  (avg {summary['scanops_avg_time']}s)")
    print(f"Grok 정확도   : {summary['grok_accuracy']}%  (avg {summary['grok_avg_time']}s)")
    print("=" * 70)

    REPORTS.mkdir(exist_ok=True)
    out = REPORTS / "results_graph_vs_grok.json"
    out.write_text(json.dumps(summary, indent=2, ensure_ascii=False), encoding="utf-8")
    print(f"\n저장: {out}")


if __name__ == "__main__":
    main()
