"""
OWASP Benchmark 최종 비교 — ScanOps(재학습 모델) vs Grok-3-mini
================================================================
production 추론 프롬프트(build_ft_user_prompt, SAFE 탈출구 포함)로 두 모델을
동일하게 평가한다. 단순 이진 판정뿐 아니라, 취약 케이스에서 CWE 종류까지
맞췄는지(실제 코드 이해도)를 함께 측정하고, 케이스별 상세를 모두 저장해
ML 보고서 작성에 사용한다.

사용:
  source .venv/bin/activate
  python scripts/benchmark_owasp_final.py --model qwen2.5-coder-security-v6:latest --tag v6
"""
from __future__ import annotations

import argparse
import json
import sys
import time
from datetime import datetime
from pathlib import Path

BASE = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(BASE))
sys.path.insert(0, str(BASE / "scripts"))

from scripts.benchmark_qwen_rag import build_ft_user_prompt, call_model, parse_response
from scripts.owasp_benchmark_cases import build_cases
from scripts.grok_client import query_llm

REPORTS = BASE / "reports"

# 카테고리 → CWE/키워드 (취약 케이스에서 '종류까지 맞췄는지' 판정용)
CAT_KW = {
    "sqli": ["sql", "89"],
    "xss": ["xss", "cross-site", "cross site", "scripting", "79", "80"],
    "cmdi": ["command", "78", "77"],
    "pathtraver": ["path travers", "directory travers", "traversal", "22", "23", "36"],
    "crypto": ["crypto", "weak encrypt", "327", "cipher", " des", "broken"],
    "hash": ["hash", "md5", "sha-1", "sha1", "328", "326"],
    "ldapi": ["ldap", "90"],
    "xpathi": ["xpath", "643"],
    "trustbound": ["trust bound", "501"],
    "securecookie": ["cookie", "secure flag", "614", "311", "315", "1004"],
    "weakrand": ["random", "330", "338", "predictable"],
}


def _no_vuln(v: str | None) -> bool:
    if not v or v in ("—", "N/A", ""):
        return True
    return v.strip().upper().startswith("NONE")


def _cat_match(cwe_text: str, cat: str) -> bool:
    t = (cwe_text or "").lower()
    return any(k in t for k in CAT_KW.get(cat, []))


def judge_scanops(case: dict, model: str) -> dict:
    t0 = time.time()
    try:
        prompt = build_ft_user_prompt(case["language"], case["code"])
        raw, _ = call_model(prompt, model, is_finetuned=True, timeout=60)
        parsed = parse_response(raw)
    except Exception as e:
        raw, parsed = f"ERROR: {e}", {}
    vuln = parsed.get("VULNERABILITY", "—")
    return {"flagged": not _no_vuln(vuln), "vuln": vuln[:70],
            "elapsed": round(time.time() - t0, 2), "raw": raw[:300]}


def judge_grok(case: dict) -> dict:
    t0 = time.time()
    prompt = build_ft_user_prompt(case["language"], case["code"])
    try:
        raw, _ = query_llm(
            prompt=prompt,
            system_prompt="You are a precise security code analyzer. Follow the output format exactly; if the code is safe respond VULNERABILITY: NONE.",
            model="grok-3-mini", temperature=0.0, max_tokens=400,
        )
    except Exception as e:
        raw = f"ERROR: {e}"
    parsed = parse_response(raw)
    vuln = parsed.get("VULNERABILITY", "—")
    return {"flagged": not _no_vuln(vuln), "vuln": vuln[:70],
            "elapsed": round(time.time() - t0, 2), "raw": raw[:300]}


def score(rows: list[dict], key: str) -> dict:
    tp = sum(1 for r in rows if r["label"] == "vuln" and r[key]["flagged"])
    fn = sum(1 for r in rows if r["label"] == "vuln" and not r[key]["flagged"])
    fp = sum(1 for r in rows if r["label"] == "safe" and r[key]["flagged"])
    tn = sum(1 for r in rows if r["label"] == "safe" and not r[key]["flagged"])
    nv, ns = tp + fn, fp + tn
    cwe_right = sum(1 for r in rows if r["label"] == "vuln" and r[key]["flagged"]
                    and _cat_match(r[key]["vuln"], r["category"]))
    recall = tp / nv * 100 if nv else 0
    fpr = fp / ns * 100 if ns else 0
    prec = tp / (tp + fp) * 100 if (tp + fp) else 0
    acc = (tp + tn) / len(rows) * 100 if rows else 0
    f1 = 2 * prec * recall / (prec + recall) if (prec + recall) else 0
    avg_t = round(sum(r[key]["elapsed"] for r in rows) / len(rows), 2)
    return {"tp": tp, "fn": fn, "fp": fp, "tn": tn,
            "detection_recall": round(recall, 1), "false_positive_rate": round(fpr, 1),
            "precision": round(prec, 1), "accuracy": round(acc, 1), "f1": round(f1, 1),
            "cwe_category_correct": cwe_right, "cwe_category_pct": round(100 * cwe_right / nv, 1) if nv else 0,
            "avg_time": avg_t}


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--model", default="qwen2.5-coder-security-v6:latest")
    ap.add_argument("--tag", default="v6")
    ap.add_argument("--skip-grok", action="store_true")
    args = ap.parse_args()

    cases = build_cases()
    print(f"OWASP 최종 비교 — {len(cases)}케이스, ScanOps 모델={args.model}")

    rows = []
    for i, c in enumerate(cases, 1):
        so = judge_scanops(c, args.model)
        gk = {"flagged": None, "vuln": "", "elapsed": 0, "raw": ""} if args.skip_grok else judge_grok(c)
        rows.append({"id": c["id"], "label": c["label"], "category": c["category"],
                     "language": c["language"], "expected_vuln": c["expected_vuln"],
                     "cwe": c["cwe"], "code": c["code"][:500],
                     "scanops": so, "grok": gk})
        st = "VULN" if so["flagged"] else "SAFE"
        truth = "VULN" if c["label"] == "vuln" else "SAFE"
        ok = "OK" if st == truth else "XX"
        print(f"  [{i:3}/{len(cases)}] {ok} {c['category']:11} truth={truth} scanops={st} {so['vuln'][:35]}")

    so_m = score(rows, "scanops")
    print("\n" + "=" * 70)
    print(f"ScanOps {args.tag}: 정확도={so_m['accuracy']}% 탐지율={so_m['detection_recall']}% "
          f"오탐률={so_m['false_positive_rate']}% CWE정확={so_m['cwe_category_pct']}% F1={so_m['f1']} avg={so_m['avg_time']}s")
    summary = {"generated": datetime.now().isoformat(timespec="seconds"),
               "source": "OWASP Benchmark v1.2 (external)", "model": args.model,
               "n_cases": len(cases), "scanops_metrics": so_m, "cases": rows}
    if not args.skip_grok:
        gk_m = score(rows, "grok")
        print(f"Grok-3-mini : 정확도={gk_m['accuracy']}% 탐지율={gk_m['detection_recall']}% "
              f"오탐률={gk_m['false_positive_rate']}% CWE정확={gk_m['cwe_category_pct']}% F1={gk_m['f1']} avg={gk_m['avg_time']}s")
        summary["grok_metrics"] = gk_m
    print("=" * 70)

    out = REPORTS / f"results_owasp_final_{args.tag}.json"
    out.write_text(json.dumps(summary, indent=2, ensure_ascii=False), encoding="utf-8")
    print(f"저장: {out}")


if __name__ == "__main__":
    main()
