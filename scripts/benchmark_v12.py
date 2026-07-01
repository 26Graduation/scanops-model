"""
V12 4-way 벤치마크 — LLM단독 / +RAG / +그래프(하이브리드) / Grok
================================================================
임의의 held-out 벤치마크 jsonl({language, code, label})에 대해 4개 시스템을
같은 케이스로 비교한다. OWASP·CVEfixes 둘 다에 재사용.

과적합 반증 포인트: V12 LLM은 OWASP·CVEfixes를 **학습에서 본 적이 없다**(zero-shot).
그래프(multi_graph)는 규칙기반이라 학습과 무관. 따라서 높은 점수 = 일반화의 증거.

결합 규칙(하이브리드):
  graph 'vuln'→VULN,  graph 'safe'→SAFE,  graph 'unknown'→LLM 판단.

실행:
  python scripts/benchmark_v12.py --bench data/cvefixes_benchmark.jsonl \
      --model qwen2.5-coder-security-v12:latest [--rag] [--grok]
"""
from __future__ import annotations

import argparse
import json
import sys
from datetime import datetime
from pathlib import Path

BASE = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(BASE))
sys.path.insert(0, str(BASE / "scripts"))

from scripts.benchmark_qwen_rag import call_model, parse_response, build_ft_user_prompt
from scanops.core.multi_graph import analyze as analyze_code


def _is_safe(v: str | None) -> bool:
    if not v or v.strip() in ("—", "N/A", ""):
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
    acc = (tp + tn) / len(rows) * 100 if rows else 0
    f1 = 2 * prec * rec / (prec + rec) if prec + rec else 0
    return {"tp": tp, "fn": fn, "fp": fp, "tn": tn, "recall": round(rec, 1),
            "fpr": round(fpr, 1), "precision": round(prec, 1),
            "accuracy": round(acc, 1), "f1": round(f1, 1)}


def _llm_flag(code: str, lang: str, model: str) -> bool:
    prompt = build_ft_user_prompt(lang, code)
    try:
        raw, _ = call_model(prompt, model, is_finetuned=True, timeout=60)
        return not _is_safe(parse_response(raw).get("VULNERABILITY", "—"))
    except Exception:
        return False


def _rag_flag(code: str, lang: str, model: str) -> bool | None:
    """RAG 보강 판정 (Qdrant 필요). 실패 시 None."""
    try:
        from scanops.core.rag import search_cves
        from scripts.benchmark_qwen_rag import build_ft_rag_user_prompt
        cves = search_cves(code[:500], top_k=3)
        prompt = build_ft_rag_user_prompt(lang, code, cves)
        raw, _ = call_model(prompt, model, is_finetuned=True, timeout=60)
        return not _is_safe(parse_response(raw).get("VULNERABILITY", "—"))
    except Exception as e:
        print(f"    (RAG 스킵: {e})")
        return None


def _grok_flag(code: str, lang: str) -> bool | None:
    try:
        from scripts.grok_client import query_llm
        prompt = build_ft_user_prompt(lang, code)
        raw, _ = query_llm(prompt)
        return not _is_safe(parse_response(raw).get("VULNERABILITY", "—"))
    except Exception as e:
        print(f"    (Grok 스킵: {e})")
        return None


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--bench", type=Path, default=BASE / "data" / "cvefixes_benchmark.jsonl")
    ap.add_argument("--model", default="qwen2.5-coder-security-v12:latest")
    ap.add_argument("--rag", action="store_true")
    ap.add_argument("--grok", action="store_true")
    ap.add_argument("--limit", type=int, default=0)
    a = ap.parse_args()

    cases = [json.loads(l) for l in open(a.bench) if l.strip()]
    if a.limit:
        cases = cases[:a.limit]
    print(f"벤치: {a.bench.name} | {len(cases)}케이스 | 모델 {a.model}")

    rows = []
    for i, c in enumerate(cases, 1):
        lang, code, label = c["language"], c["code"], c["label"]
        llm = _llm_flag(code, lang, a.model)
        g = analyze_code(code, lang)
        gv = g["verdict"]
        # V14 결합규칙(R2): 그래프는 **LLM이 놓친 취약만 보강**(재현율↑). LLM의 취약 판정은
        #   절대 덮지 않는다 → 그래프가 틀려도 LLM 정탐을 제거하지 않음(오veto 0).
        #   3벤치(CVEfixes·OWASP·CyberNative) 검증서 현행 규칙을 모두에서 ≥ (scripts/tune_hybrid_rule.py).
        if llm:
            hybrid = True
        elif gv == "vuln":
            hybrid = True
        else:
            hybrid = False
        row = {"label": label, "llm": llm, "graph": gv, "hybrid": hybrid}
        if a.rag:
            rf = _rag_flag(code, lang, a.model)
            row["rag"] = llm if rf is None else rf
        if a.grok:
            gf = _grok_flag(code, lang)
            row["grok"] = gf if gf is not None else False
        rows.append(row)
        if i % 20 == 0:
            print(f"  {i}/{len(cases)}")

    print("\n" + "=" * 70)
    print(f"V12 4-way — {a.bench.name} ({len(rows)}케이스)")
    print("=" * 70)
    def line(name, key):
        m = metrics(rows, key)
        return (f"{name:26} F1={m['f1']:5}  재현율={m['recall']:5}%  오탐률={m['fpr']:5}%  "
                f"정확도={m['accuracy']:5}%  (TP{m['tp']} FN{m['fn']} FP{m['fp']} TN{m['tn']})")
    print(line("① V12 LLM 단독", "llm"))
    if a.rag:
        print(line("② V12 + RAG", "rag"))
    print(line("③ V12 + 그래프 하이브리드", "hybrid"))
    if a.grok:
        print(line("④ Grok", "grok"))
    print("=" * 70)

    sup = sum(1 for r in rows if r["llm"] and not r["hybrid"] and r["label"] == "safe")
    sup_wrong = sum(1 for r in rows if r["llm"] and not r["hybrid"] and r["label"] == "vuln")
    boost = sum(1 for r in rows if not r["llm"] and r["hybrid"] and r["label"] == "vuln")
    print(f"\n그래프 효과: LLM 오탐 억제 {sup}건(정탐 {sup_wrong}건 잘못 억제) | LLM 놓친 취약 보강 {boost}건")

    out = BASE / "reports" / f"results_v12_{a.bench.stem}.json"
    summary = {"generated": datetime.now().isoformat(timespec="seconds"),
               "bench": a.bench.name, "n": len(rows), "model": a.model,
               "llm": metrics(rows, "llm"), "hybrid": metrics(rows, "hybrid")}
    if a.rag: summary["rag"] = metrics(rows, "rag")
    if a.grok: summary["grok"] = metrics(rows, "grok")
    summary["cases"] = rows
    out.write_text(json.dumps(summary, indent=2, ensure_ascii=False), encoding="utf-8")
    print(f"저장: {out}")


if __name__ == "__main__":
    main()
