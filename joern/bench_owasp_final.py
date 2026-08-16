"""Phase 2 Q2 — taint 전용 벤치(OWASP Benchmark 110건)에서 Joern v4 단독 성능.

[사전 등록 — 실행 전 확정]
  지표: precision / recall / FPR / F1 / 자명 기준선(all-vuln, all-safe) / 부트스트랩 95% CI
  대상: data/owasp_holdout_bench.jsonl (Java 110건, vuln 55 / safe 55)
  arm : Joern v4 단독 (verdict == "vuln" → 취약 예측)
  주의: 이 숫자는 **taint 계열 취약점 한정** 성능이며 CleanVul 숫자와 섞지 않는다.

출력: rebuild/out/owasp_joern_v4_final.jsonl / owasp_joern_v4_final_metrics.json
"""
from __future__ import annotations

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
from joern.sanitizer_spec import write_san_file  # noqa: E402

if Path(_ACTIVE).name != "taint_v4.sc":
    raise SystemExit(f"[owasp] FATAL: 활성 쿼리가 v4 가 아니다 → {_ACTIVE}")

OUT = ROOT / "rebuild" / "out"
SEED = 42


def boot_ci(hits: int, n: int, iters: int = 2000) -> list[float]:
    if n == 0:
        return [0.0, 0.0]
    rng = random.Random(SEED)
    obs = [1] * hits + [0] * (n - hits)
    vals = sorted(sum(rng.choice(obs) for _ in range(n)) / n for _ in range(iters))
    return [round(vals[int(0.025 * iters)], 4), round(vals[int(0.975 * iters) - 1], 4)]


def metrics(pred: list[str], gold: list[str]) -> dict:
    tp = sum(1 for p, g in zip(pred, gold) if p == "vuln" and g == "vuln")
    fp = sum(1 for p, g in zip(pred, gold) if p == "vuln" and g == "safe")
    fn = sum(1 for p, g in zip(pred, gold) if p == "safe" and g == "vuln")
    tn = sum(1 for p, g in zip(pred, gold) if p == "safe" and g == "safe")
    prec = tp / (tp + fp) if (tp + fp) else 0.0
    rec = tp / (tp + fn) if (tp + fn) else 0.0
    fpr = fp / (fp + tn) if (fp + tn) else 0.0
    f1 = 2 * prec * rec / (prec + rec) if (prec + rec) else 0.0
    return {"n": len(pred), "tp": tp, "fp": fp, "fn": fn, "tn": tn,
            "precision": round(prec, 4), "precision_ci95": boot_ci(tp, tp + fp),
            "recall": round(rec, 4), "fpr": round(fpr, 4), "f1": round(f1, 4)}


def main() -> int:
    src = ROOT / "data" / "owasp_holdout_bench.jsonl"
    rows = [json.loads(l) for l in src.open()]
    print(f"[owasp] {len(rows)}건 (vuln {sum(1 for r in rows if r['label']=='vuln')} / "
          f"safe {sum(1 for r in rows if r['label']=='safe')})", flush=True)

    out_path = OUT / "owasp_joern_v4_final.jsonl"
    done: dict[str, dict] = {}
    if out_path.exists():
        for line in out_path.open():
            try:
                o = json.loads(line)
                done[o["case_id"]] = o
            except Exception:  # noqa: BLE001
                pass

    lang = rows[0]["language"]
    r = resolve(lang)
    if r is None:
        raise SystemExit(f"[owasp] 지원하지 않는 언어: {lang}")
    jl = r[1]
    san_dir = Path(os.getenv("TMPDIR", "/tmp")) / "scanops_final_san"
    san_dir.mkdir(parents=True, exist_ok=True)
    p = san_dir / f"{jl}.txt"
    n_pat = write_san_file(jl, p)
    os.environ["JOERN_SANITIZER_FILE"] = str(p)
    print(f"[owasp] sanFile {jl}: {n_pat} patterns", flush=True)

    todo = [(f"owasp_{i}", r_) for i, r_ in enumerate(rows)
            if f"owasp_{i}" not in done]
    t0 = time.time()
    with out_path.open("a") as fh:
        for i in range(0, len(todo), 25):
            batch = todo[i:i + 25]
            res = analyze_batch(f"owasp_{i}_{int(time.time())}", lang,
                                [{"path": cid, "content": rr["code"]} for cid, rr in batch],
                                chunk_size=25)
            for cid, rr in batch:
                v = res["results"].get(cid, {})
                fh.write(json.dumps({
                    "case_id": cid, "label": rr["label"], "lang": lang,
                    "joern_verdict": v.get("verdict", "unknown"),
                    "categories": v.get("categories", []),
                    "sanitized_categories": v.get("sanitized_categories", []),
                    "unknown_reason": v.get("unknown_reason"),
                    "wrap_level": v.get("wrap_level"),
                }, ensure_ascii=False) + "\n")
                done[cid] = {"label": rr["label"], "joern_verdict": v.get("verdict", "unknown"),
                             "categories": v.get("categories", [])}
            fh.flush()
            print(f"[owasp] {i+len(batch)}/{len(todo)} {(time.time()-t0)/60:.1f}분", flush=True)

    allr = [json.loads(l) for l in out_path.open()]
    gold = [r_["label"] for r_ in allr]
    arms = {
        "all-vuln (자명)": ["vuln"] * len(allr),
        "all-safe (자명)": ["safe"] * len(allr),
        "Joern v4 단독": ["vuln" if r_["joern_verdict"] == "vuln" else "safe" for r_ in allr],
    }
    import collections
    result = {
        "bench": "OWASP Benchmark holdout (Java, taint 계열)",
        "n": len(allr),
        "verdict_dist": dict(collections.Counter(r_["joern_verdict"] for r_ in allr)),
        "category_dist": dict(collections.Counter(
            c for r_ in allr for c in (r_.get("categories") or []))),
        "arms": {k: metrics(v, gold) for k, v in arms.items()},
        "note": ("OWASP 는 합성 벤치다. 자체 정규식 graph 는 여기에 손튜닝된 이력이 있으나, "
                 "Joern v4 쿼리(taint_v4.sc·sanitizers.json)는 OWASP 를 보고 만들지 않았다 "
                 "— CleanVul 실패 사례에서만 도출됐다(커밋 이력으로 확인 가능)."),
    }
    (OUT / "owasp_joern_v4_final_metrics.json").write_text(
        json.dumps(result, indent=2, ensure_ascii=False))
    print(json.dumps(result, indent=2, ensure_ascii=False))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
