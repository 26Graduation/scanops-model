"""
V4-TRAIN 판정 — 사양 rebuild/V4_TRAIN_RUN_SPEC.md §4 + §10-2
=============================================================
게이트(전부 결과 보기 전 커밋 `b6ea0d1`):
  V4-TRAIN-PASS/PARTIAL/FAIL  외부 2개 벤치 AUC ≥ 0.75 (§4)
  TARGET-MET                  CleanVul_v2 report AUC ≥ 0.75 (§10-2)
  ADOPT                       ① 내부 test ΔAUC CI 하한 > 0
                              ② CleanVul_v2 report ΔAUC CI 하한 > 0
                              ③ PrimeVul report ΔAUC 점추정 ≥ 0
                              — **기준선 v3s42@750 과 v1 둘 다**에 대해 성립
  NO-ADOPT                    그 외 → v1 유지

ΔAUC 는 **쌍 부트스트랩 2,000회**(같은 아이템 재표집으로 두 모델을 함께 태운다).
쌍 데이터(pair_id)는 쌍 단위로 재표집한다 — bootstrap_ci.py 규약.

실행: python3 rebuild/v4_judge.py [new_tag]      (기본 v4s42)
출력: out/v4_metrics.json
"""
from __future__ import annotations

import json
import random
import sys
from collections import defaultdict
from pathlib import Path

ROOT = Path(__file__).resolve().parent
sys.path.insert(0, str(ROOT))

from sweep_threshold import auc  # noqa: E402

NEW = sys.argv[1] if len(sys.argv) > 1 else "v4s42"
BASELINES = ["v3s42", "v1"]          # §10-2 — 둘 다에 대해 성립해야 ADOPT
N_BOOT, SEED = 2000, 42
TARGET_AUC = 0.75

SPLITS = [
    ("test",               "내부 test",           "ci"),     # ① CI 하한 > 0
    ("cleanvul_v2_report", "CleanVul_v2 report",  "ci"),     # ② CI 하한 > 0
    ("primevul_report",    "PrimeVul report",     "point"),  # ③ 점추정 ≥ 0
]
EXTRA = [("cvefixes157", "CVEfixes 157"), ("cybernative154", "CyberNative 154")]
EXTERNAL_FOR_GATE = ["primevul_report", "cleanvul_v2_report"]   # §4


def load(tag: str, split: str) -> list[dict] | None:
    p = ROOT / "out" / f"{tag}_logprob_{split}.jsonl"
    return [json.loads(l) for l in p.open()] if p.exists() else None


def units(items: list[dict]) -> list[list[int]]:
    if items and items[0]["meta"].get("pair_id"):
        g = defaultdict(list)
        for i, r in enumerate(items):
            g[r["meta"]["pair_id"]].append(i)
        return list(g.values())
    return [[i] for i in range(len(items))]


def paired_delta_auc(new: list[dict], base: list[dict],
                     n: int = N_BOOT, seed: int = SEED) -> dict:
    """같은 재표집 인덱스로 두 모델의 AUC 를 함께 재서 ΔAUC 분포를 본다."""
    assert len(new) == len(base), "두 파일의 케이스 수가 다르다"
    # 아이템 정렬이 같은지 확인 — 다르면 비교 자체가 성립하지 않는다
    for a, b in zip(new[:50], base[:50]):
        assert a["meta"].get("pair_id") == b["meta"].get("pair_id") and \
               a["meta"]["label"] == b["meta"]["label"], "두 파일의 아이템 순서가 다르다"
    us = units(new)
    rng = random.Random(seed)
    ds = []
    for _ in range(n):
        idx = [i for _ in range(len(us)) for i in us[rng.randrange(len(us))]]
        ds.append(auc([new[i] for i in idx]) - auc([base[i] for i in idx]))
    ds.sort()
    lo, hi = int(n * 0.025), int(n * 0.975)
    return {"auc_new": auc(new), "auc_base": auc(base),
            "delta_point": round(auc(new) - auc(base), 4),
            "delta_ci95": [round(ds[lo], 4), round(ds[hi], 4)],
            "ci_lower_gt_0": ds[lo] > 0}


def main() -> None:
    out: dict = {"spec": "rebuild/V4_TRAIN_RUN_SPEC.md §4·§10-2",
                 "new_tag": NEW, "baselines": BASELINES,
                 "n_boot": N_BOOT, "seed": SEED, "target_auc": TARGET_AUC,
                 "auc": {}, "delta": {}, "missing": []}

    # ── 절대 AUC (§4 게이트) ────────────────────────────────────────────────
    for split, label, _ in SPLITS + [(s, l, None) for s, l in EXTRA]:
        recs = load(NEW, split)
        if recs is None:
            out["missing"].append(split)
            continue
        out["auc"][split] = {"label": label, "n": len(recs), "auc": auc(recs)}
        print(f"[{label}] n={len(recs)} AUC={auc(recs)}")

    ext = [out["auc"][s]["auc"] for s in EXTERNAL_FOR_GATE if s in out["auc"]]
    n_pass = sum(1 for a in ext if a >= TARGET_AUC)
    out["gate_section4"] = ("V4-TRAIN-PASS" if n_pass == 2 else
                            "V4-TRAIN-PARTIAL" if n_pass == 1 else "V4-TRAIN-FAIL")
    cvr = out["auc"].get("cleanvul_v2_report", {}).get("auc")
    out["TARGET_MET"] = bool(cvr is not None and cvr >= TARGET_AUC)

    # ── ΔAUC (§10-2 ADOPT) ──────────────────────────────────────────────────
    adopt_ok = True
    for base in BASELINES:
        out["delta"][base] = {}
        for split, label, mode in SPLITS:
            a, b = load(NEW, split), load(base, split)
            if a is None or b is None:
                out["delta"][base][split] = {"status": "미실행 — 파일 없음"}
                adopt_ok = False
                continue
            d = paired_delta_auc(a, b)
            d["mode"] = mode
            d["passes"] = d["ci_lower_gt_0"] if mode == "ci" else (d["delta_point"] >= 0)
            out["delta"][base][split] = d
            adopt_ok = adopt_ok and d["passes"]
            print(f"  Δ vs {base} [{label}] {d['auc_base']} → {d['auc_new']} "
                  f"= {d['delta_point']:+} CI{d['delta_ci95']} mode={mode} pass={d['passes']}")

    out["ADOPT"] = "ADOPT" if adopt_ok else "NO-ADOPT"

    # ── DOSE 외삽 검정 (§4 부가 판정 1) ─────────────────────────────────────
    out["dose_extrapolation_check"] = {
        "predicted": {"primevul_report": 0.6286, "cleanvul_v2_report": 0.6793},
        "observed": {k: out["auc"].get(k, {}).get("auc") for k in EXTERNAL_FOR_GATE},
        "note": "관측 < 예측 → 감속 확인(선형 외삽이 낙관적). 관측 > 예측 → 학습량만으로 "
                "설명 안 되는 이득(lr 기여 가능성. 단 사양 §3 교란으로 단정 불가)",
    }

    p = ROOT / "out" / "v4_metrics.json"
    p.write_text(json.dumps(out, ensure_ascii=False, indent=2))
    print(f"\n§4 게이트: {out['gate_section4']}   TARGET-MET: {out['TARGET_MET']}   "
          f"§10-2: {out['ADOPT']}")
    print(f"→ {p}")


if __name__ == "__main__":
    main()
