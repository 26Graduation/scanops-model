"""
ScanOps 보안 모델 평가 — 외부 표준셋(OWASP) 기준 분류 지표 산출
================================================================
보안 취약점 탐지는 이진 분류(취약 vs 안전) 문제이므로, 회귀 지표(RSS/R²)가
아니라 분류 지표로 평가한다:
  - Precision(정밀도): 취약이라고 한 것 중 실제 취약 비율
  - Recall(재현율/탐지율): 실제 취약 중 잡아낸 비율
  - F1: precision·recall의 조화평균
  - FPR(오탐률): 안전한 코드를 취약이라 잘못 경고한 비율
  - Accuracy(정확도), 혼동행렬(TP/FN/FP/TN)
  - CWE-카테고리 정확도: 단순 탐지를 넘어 '어떤 취약점인지'까지 맞췄는지

평가셋: OWASP Benchmark v1.2 — 우리가 만들지 않은 외부 표준 SAST 평가
데이터셋. 학습에 쓰지 않은 홀드아웃 110케이스(취약 55 + 안전 55).

실행:
  python -m ml.evaluate --model qwen2.5-coder-security-v8:latest --tag v8
  python -m ml.evaluate --model qwen2.5-coder-security-v8:latest --tag v8 --with-grok
"""
from __future__ import annotations

import argparse
import json
import sys
import time
from datetime import datetime
from pathlib import Path

from ml.config import REPORTS_DIR

# 검증된 추론/데이터 유틸은 기존 모듈을 재사용 (중복 구현 방지)
sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
from scripts.benchmark_qwen_rag import build_ft_user_prompt, call_model, parse_response
from scripts.owasp_benchmark_cases import build_cases
from scripts.grok_client import query_llm

# 카테고리 → CWE/키워드 (취약 케이스의 '종류 정확도' 판정)
CAT_KW = {
    "sqli": ["sql", "89"], "xss": ["xss", "cross-site", "scripting", "79", "80"],
    "cmdi": ["command", "78", "77"], "pathtraver": ["traversal", "22", "23", "36"],
    "crypto": ["crypto", "encrypt", "327", "cipher", " des", "broken"],
    "hash": ["hash", "md5", "sha-1", "sha1", "328", "326"],
    "ldapi": ["ldap", "90"], "xpathi": ["xpath", "643"],
    "trustbound": ["trust bound", "501"],
    "securecookie": ["cookie", "secure flag", "614", "311", "315", "1004"],
    "weakrand": ["random", "330", "338", "predictable"],
}


def _is_safe(vuln: str | None) -> bool:
    if not vuln or vuln in ("—", "N/A", ""):
        return True
    return vuln.strip().upper().startswith("NONE")


def _cwe_ok(vuln: str, cat: str) -> bool:
    t = (vuln or "").lower()
    return any(k in t for k in CAT_KW.get(cat, []))


def predict_scanops(case: dict, model: str) -> dict:
    t0 = time.time()
    try:
        raw, _ = call_model(build_ft_user_prompt(case["language"], case["code"]),
                            model, is_finetuned=True, timeout=60)
        vuln = parse_response(raw).get("VULNERABILITY", "—")
    except Exception as e:
        raw, vuln = f"ERROR: {e}", "—"
    return {"flagged": not _is_safe(vuln), "vuln": vuln[:70],
            "elapsed": round(time.time() - t0, 2), "raw": raw[:300]}


def predict_grok(case: dict) -> dict:
    t0 = time.time()
    try:
        raw, _ = query_llm(
            prompt=build_ft_user_prompt(case["language"], case["code"]),
            system_prompt="You are a precise security code analyzer. If the code is safe respond VULNERABILITY: NONE.",
            model="grok-3-mini", temperature=0.0, max_tokens=400)
        vuln = parse_response(raw).get("VULNERABILITY", "—")
    except Exception as e:
        raw, vuln = f"ERROR: {e}", "—"
    return {"flagged": not _is_safe(vuln), "vuln": vuln[:70],
            "elapsed": round(time.time() - t0, 2), "raw": raw[:300]}


def metrics(rows: list[dict], key: str) -> dict:
    tp = sum(1 for r in rows if r["label"] == "vuln" and r[key]["flagged"])
    fn = sum(1 for r in rows if r["label"] == "vuln" and not r[key]["flagged"])
    fp = sum(1 for r in rows if r["label"] == "safe" and r[key]["flagged"])
    tn = sum(1 for r in rows if r["label"] == "safe" and not r[key]["flagged"])
    nv, ns = tp + fn, fp + tn
    cwe_right = sum(1 for r in rows if r["label"] == "vuln" and r[key]["flagged"]
                    and _cwe_ok(r[key]["vuln"], r["category"]))
    recall = tp / nv if nv else 0
    fpr = fp / ns if ns else 0
    prec = tp / (tp + fp) if (tp + fp) else 0
    acc = (tp + tn) / len(rows) if rows else 0
    f1 = 2 * prec * recall / (prec + recall) if (prec + recall) else 0
    return {
        "confusion_matrix": {"tp": tp, "fn": fn, "fp": fp, "tn": tn},
        "precision": round(prec * 100, 1), "recall": round(recall * 100, 1),
        "f1": round(f1 * 100, 1), "false_positive_rate": round(fpr * 100, 1),
        "accuracy": round(acc * 100, 1),
        "cwe_category_accuracy": round(100 * cwe_right / nv, 1) if nv else 0,
        "avg_latency_s": round(sum(r[key]["elapsed"] for r in rows) / len(rows), 2),
    }


def by_category(rows: list[dict], key: str) -> dict:
    out: dict[str, dict] = {}
    for r in rows:
        b = out.setdefault(r["category"], {"n": 0, "correct": 0})
        b["n"] += 1
        b["correct"] += int(r[key]["flagged"] == (r["label"] == "vuln"))
    return {k: {"n": v["n"], "accuracy": round(100 * v["correct"] / v["n"], 1)} for k, v in out.items()}


def evaluate(model: str, tag: str, with_grok: bool) -> dict:
    cases = build_cases()
    print(f"[eval] OWASP 홀드아웃 {len(cases)}케이스 | 모델={model}")
    rows = []
    for i, c in enumerate(cases, 1):
        so = predict_scanops(c, model)
        gk = predict_grok(c) if with_grok else {"flagged": None, "vuln": "", "elapsed": 0, "raw": ""}
        rows.append({"id": c["id"], "label": c["label"], "category": c["category"],
                     "language": c["language"], "expected_vuln": c["expected_vuln"],
                     "cwe": c["cwe"], "code": c["code"][:500], "scanops": so, "grok": gk})
        truth = "VULN" if c["label"] == "vuln" else "SAFE"
        pred = "VULN" if so["flagged"] else "SAFE"
        print(f"  [{i:3}/{len(cases)}] {'OK' if pred==truth else 'XX'} {c['category']:11} {truth}->{pred} {so['vuln'][:30]}")

    result = {
        "generated": datetime.now().isoformat(timespec="seconds"),
        "eval_set": "OWASP Benchmark v1.2 (external holdout, 110 cases)",
        "model": model, "tag": tag, "n_cases": len(cases),
        "scanops": {"metrics": metrics(rows, "scanops"), "by_category": by_category(rows, "scanops")},
        "cases": rows,
    }
    sm = result["scanops"]["metrics"]
    print("\n" + "=" * 64)
    print(f"ScanOps {tag}: F1={sm['f1']}  정밀도={sm['precision']}%  재현율={sm['recall']}%  "
          f"오탐률={sm['false_positive_rate']}%  정확도={sm['accuracy']}%  CWE정확={sm['cwe_category_accuracy']}%")
    if with_grok:
        gm = metrics(rows, "grok")
        result["grok"] = {"metrics": gm, "by_category": by_category(rows, "grok")}
        print(f"Grok-3-mini: F1={gm['f1']}  정밀도={gm['precision']}%  재현율={gm['recall']}%  "
              f"오탐률={gm['false_positive_rate']}%  정확도={gm['accuracy']}%  CWE정확={gm['cwe_category_accuracy']}%")
    print("=" * 64)

    out = REPORTS_DIR / f"eval_owasp_{tag}.json"
    out.write_text(json.dumps(result, indent=2, ensure_ascii=False), encoding="utf-8")
    print(f"[eval] 저장: {out}")
    return result


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--model", required=True)
    ap.add_argument("--tag", required=True)
    ap.add_argument("--with-grok", action="store_true")
    args = ap.parse_args()
    evaluate(args.model, args.tag, args.with_grok)


if __name__ == "__main__":
    main()
