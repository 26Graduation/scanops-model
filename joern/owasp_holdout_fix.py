"""Phase 3-d — OWASP 홀드아웃 55건 **1회만** 평가 (사전 등록).

[사전 등록 — 실행 전 확정, 결과 본 뒤 변경 금지]
  IMPROVED     : FPR <= 0.50 AND recall >= 0.75
  NOT-IMPROVED : 그 외. 패턴 유지, 결과 그대로 기록.
  비교 대상: 어제 전건(110) Joern v4 = precision 0.5172 / recall 0.8182 / FPR 0.7636

출력: rebuild/out/owasp_holdout_v4fix.jsonl / owasp_holdout_v4fix_metrics.json
"""
from __future__ import annotations

import collections
import json
import os
import random
import sys
import time
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))
os.environ["JOERN_SCRIPT"] = str(ROOT / "joern" / "queries" / "taint_v4.sc")

from joern.handler_joern import SCRIPT as _ACTIVE, analyze_batch  # noqa: E402
from joern.langmap import resolve  # noqa: E402
from joern.owasp_split_fix import category_of  # noqa: E402
from joern.sanitizer_spec import write_san_file  # noqa: E402

if Path(_ACTIVE).name != "taint_v4.sc":
    raise SystemExit(f"FATAL: {_ACTIVE}")

OUT = ROOT / "rebuild" / "out"
SEED = 42


def boot_ci(hits, n, iters=2000):
    if n == 0:
        return [0.0, 0.0]
    rng = random.Random(SEED)
    obs = [1] * hits + [0] * (n - hits)
    v = sorted(sum(rng.choice(obs) for _ in range(n)) / n for _ in range(iters))
    return [round(v[int(0.025 * iters)], 4), round(v[int(0.975 * iters) - 1], 4)]


def metrics(pred, gold):
    tp = sum(1 for p, g in zip(pred, gold) if p == "vuln" and g == "vuln")
    fp = sum(1 for p, g in zip(pred, gold) if p == "vuln" and g == "safe")
    fn = sum(1 for p, g in zip(pred, gold) if p == "safe" and g == "vuln")
    tn = sum(1 for p, g in zip(pred, gold) if p == "safe" and g == "safe")
    pr = tp / (tp + fp) if (tp + fp) else 0.0
    rc = tp / (tp + fn) if (tp + fn) else 0.0
    fpr = fp / (fp + tn) if (fp + tn) else 0.0
    f1 = 2 * pr * rc / (pr + rc) if (pr + rc) else 0.0
    return {"n": len(pred), "tp": tp, "fp": fp, "fn": fn, "tn": tn,
            "precision": round(pr, 4), "precision_ci95": boot_ci(tp, tp + fp),
            "recall": round(rc, 4), "fpr": round(fpr, 4), "f1": round(f1, 4)}


def main() -> int:
    rows = [json.loads(l) for l in (ROOT / "data" / "owasp_holdout_bench.jsonl").open()]
    split = json.loads((OUT / "owasp_split_fix.json").read_text())
    idxs = split["holdout"]
    cases = [(f"owasph_{i}", rows[i]) for i in idxs]
    print(f"[hold] 홀드아웃 {len(cases)}건 — 1회만 연다", flush=True)

    out_path = OUT / "owasp_holdout_v4fix.jsonl"
    done = {}
    if out_path.exists():
        for line in out_path.open():
            o = json.loads(line)
            done[o["case_id"]] = o

    lang = rows[0]["language"]
    jl = resolve(lang)[1]
    san_dir = Path(os.getenv("TMPDIR", "/tmp")) / "scanops_fix_san"
    san_dir.mkdir(parents=True, exist_ok=True)
    p = san_dir / f"{jl}.txt"
    n = write_san_file(jl, p)
    os.environ["JOERN_SANITIZER_FILE"] = str(p)
    print(f"[hold] sanFile {jl}: {n} patterns", flush=True)

    todo = [(cid, r) for cid, r in cases if cid not in done]
    t0 = time.time()
    with out_path.open("a") as fh:
        for i in range(0, len(todo), 25):
            b = todo[i:i + 25]
            res = analyze_batch(f"hold_{i}_{int(time.time())}", lang,
                                [{"path": cid, "content": r["code"]} for cid, r in b],
                                chunk_size=25)
            for cid, r in b:
                v = res["results"].get(cid, {})
                rec = {"case_id": cid, "label": r["label"], "cat": category_of(r["code"]),
                       "joern_verdict": v.get("verdict", "unknown"),
                       "categories": v.get("categories", []),
                       "sanitized_categories": v.get("sanitized_categories", [])}
                fh.write(json.dumps(rec, ensure_ascii=False) + "\n")
                done[cid] = rec
            fh.flush()
            print(f"[hold] {i+len(b)}/{len(todo)} {(time.time()-t0)/60:.1f}분", flush=True)

    recs = [done[cid] for cid, _ in cases if cid in done]
    gold = [r["label"] for r in recs]
    pred = ["vuln" if r["joern_verdict"] == "vuln" else "safe" for r in recs]
    m = metrics(pred, gold)
    improved = (m["fpr"] <= 0.50 and m["recall"] >= 0.75)
    result = {
        "split": "holdout", "n": len(recs),
        "gate_preregistered": "IMPROVED = FPR <= 0.50 AND recall >= 0.75",
        "verdict": "IMPROVED" if improved else "NOT-IMPROVED",
        "metrics": m,
        "trivial_all_vuln": metrics(["vuln"] * len(recs), gold),
        "verdict_dist": dict(collections.Counter(r["joern_verdict"] for r in recs)),
        "baseline_full110_v4": {"precision": 0.5172, "recall": 0.8182, "fpr": 0.7636},
    }
    (OUT / "owasp_holdout_v4fix_metrics.json").write_text(
        json.dumps(result, indent=2, ensure_ascii=False))
    print(json.dumps(result, indent=2, ensure_ascii=False))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())

