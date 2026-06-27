"""
OWASP 하이브리드 벤치마크 — v11(LLM 탐지) + Java 그래프(오탐 억제) vs Grok
================================================================
핵심 가설 검증: LLM은 OWASP에서 안전/취약을 못 가리지만(재현율≈오탐률),
Java taint 그래프는 가린다(vuln 정밀도 95.7%, FPR 12.7%). 둘을 합치면?

결합 규칙 (그래프의 신뢰도 프로파일 기반):
  - 그래프가 'vuln' 확정(정밀도 95.7%)  → VULN (LLM이 놓쳐도 보강)
  - 그래프가 'safe' 확정              → SAFE (LLM 오탐을 그래프가 veto)
  - 그래프가 'unknown'(판정 불가)     → LLM 판단에 위임

비교: ① v11 LLM 단독  ② v11+그래프 하이브리드  ③ Grok-3-mini(기존 수치)

실행:
  python scripts/benchmark_hybrid_owasp.py
"""
from __future__ import annotations

import json
import re
import sys
from datetime import datetime
from pathlib import Path

BASE = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(BASE))
sys.path.insert(0, str(BASE / "scripts"))

from scripts.benchmark_qwen_rag import call_model, parse_response
from scanops.core.java_graph import analyze_java

REPORTS = BASE / "reports"
MODEL_V11 = "qwen2.5-coder-security-v11:latest"

# Grok-3-mini 기존 측정(같은 프롬프트, ml/evaluate 결과)
GROK = {"recall": 60.0, "fpr": 30.9, "precision": 66.0, "accuracy": 64.5, "f1": 62.9}


def _is_safe_vuln(v: str | None) -> bool:
    if not v or v in ("—", "N/A", ""):
        return True
    return v.strip().upper().startswith("NONE")


def metrics(rows: list[dict], key: str) -> dict:
    tp = sum(1 for r in rows if r["label"] == "vuln" and r[key])
    fn = sum(1 for r in rows if r["label"] == "vuln" and not r[key])
    fp = sum(1 for r in rows if r["label"] == "safe" and r[key])
    tn = sum(1 for r in rows if r["label"] == "safe" and not r[key])
    rec = tp / (tp + fn) * 100 if tp + fn else 0
    fpr = fp / (fp + tn) * 100 if fp + tn else 0
    prec = tp / (tp + fp) * 100 if tp + fp else 0
    acc = (tp + tn) / len(rows) * 100
    f1 = 2 * prec * rec / (prec + rec) if prec + rec else 0
    return {"tp": tp, "fn": fn, "fp": fp, "tn": tn, "recall": round(rec, 1),
            "fpr": round(fpr, 1), "precision": round(prec, 1),
            "accuracy": round(acc, 1), "f1": round(f1, 1)}


def main():
    llm_cases = json.load(open(BASE / "data" / "owasp_holdout_eval.json"))     # LLM 프롬프트
    full = {c["id"]: c for c in json.load(open(BASE / "data" / "owasp_holdout_full.json"))}  # 그래프용 전체파일

    rows = []
    for i, c in enumerate(llm_cases, 1):
        # ① LLM(v11) 판정
        try:
            raw, _ = call_model(c["prompt"], MODEL_V11, is_finetuned=True, timeout=60)
            vuln = parse_response(raw).get("VULNERABILITY", "—")
        except Exception:
            vuln = "—"
        llm_flag = not _is_safe_vuln(vuln)

        # ② 그래프 판정 (전체 파일)
        g = analyze_java(full[c["id"]]["full_code"]) if c["id"] in full else {"verdict": "unknown"}
        gv = g["verdict"]

        # ③ 하이브리드 결합 (decoy-aware 그래프 기준):
        #   - 그래프 vuln 확정(정밀도 97.6%)  → VULN (LLM이 놓쳐도 보강)
        #   - 그래프 safe 확정(정밀도 100%)   → SAFE (LLM 오탐을 veto)
        #   - 그래프 unknown(판정 불가)       → LLM 판단에 위임
        # java_graph가 OWASP 미끼(decoy)를 풀어내며 safe 정밀도 100%를 달성해,
        # 모든 graph-safe를 안전하게 veto할 수 있게 됨(기존 고신뢰-only veto 대체).
        if gv == "vuln":
            hybrid_flag = True
        elif gv == "safe":
            hybrid_flag = False
        else:  # unknown
            hybrid_flag = llm_flag

        rows.append({"id": c["id"], "label": c["label"], "category": c["category"],
                     "llm": llm_flag, "graph": gv, "hybrid": hybrid_flag})
        if i % 20 == 0:
            print(f"  {i}/{len(llm_cases)}")

    m_llm = metrics(rows, "llm")
    m_hyb = metrics(rows, "hybrid")

    print("\n" + "=" * 66)
    print("OWASP 110케이스 — v11 단독 vs 하이브리드 vs Grok")
    print("=" * 66)
    def line(name, m):
        return (f"{name:24} F1={m['f1']:5}  재현율={m['recall']:5}%  오탐률={m['fpr']:5}%  "
                f"정확도={m['accuracy']:5}%  (TP{m['tp']} FN{m['fn']} FP{m['fp']} TN{m['tn']})")
    print(line("① v11 LLM 단독", m_llm))
    print(line("② v11 + 그래프 하이브리드", m_hyb))
    print(f"{'③ Grok-3-mini':24} F1={GROK['f1']}  재현율={GROK['recall']}%  오탐률={GROK['fpr']}%  정확도={GROK['accuracy']}%")
    print("=" * 66)

    # 그래프가 LLM 오탐을 억제한 건수
    suppressed = sum(1 for r in rows if r["llm"] and not r["hybrid"] and r["label"] == "safe")
    suppressed_wrong = sum(1 for r in rows if r["llm"] and not r["hybrid"] and r["label"] == "vuln")
    print(f"\n그래프가 LLM 오탐 억제: 안전 {suppressed}건 정탐 억제 / 취약 {suppressed_wrong}건 잘못 억제")

    out = REPORTS / "results_hybrid_owasp.json"
    out.write_text(json.dumps({
        "generated": datetime.now().isoformat(timespec="seconds"),
        "llm_metrics": m_llm, "hybrid_metrics": m_hyb, "grok_metrics": GROK,
        "cases": rows,
    }, indent=2, ensure_ascii=False), encoding="utf-8")
    print(f"저장: {out}")


if __name__ == "__main__":
    main()
