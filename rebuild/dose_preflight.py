"""
DOSE — 학습량-판별력 용량반응 사전검증 (사양서 rebuild/DOSE_RUN_SPEC.md)
========================================================================
질문: 학습을 더 하면 외부 AUC 가 오르는가. (#4 수렴 학습, $8 의 전제)

동일 실행 v3s42 의 step 450 / 750 두 체크포인트가 세 벤치에서 채점돼 있다.
같은 시드·같은 데이터·같은 하이퍼파라미터, 학습량만 +67%.

비용 $0 — 기존 산출물만 읽는다. 새 추론 없음.
실행: python3 rebuild/dose_preflight.py
출력: out/dose_metrics.json
"""
from __future__ import annotations

import json
import random
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent
sys.path.insert(0, str(ROOT))

from sweep_threshold import auc  # noqa: E402  — 동점 처리까지 동일해야 비교가 성립

SEED = 42
N_BOOT = 2000
TOTAL_STEPS = 1674      # 계획 총 step (로그 진행률 표시)
STEP_A, STEP_B = 450, 750
TARGET_AUC = 0.75       # V3_RESULTS.md §10 이 제시한 새 목표 (참조선, 게이트 아님)

# 사양서 §4 건전성 검사 — step 750 이 기존 보고를 재현해야 한다
SANITY = {"primevul_report": 0.580, "cleanvul_v2_report": 0.621, "test": 0.887}
SANITY_TOL = 0.005

# (split 이름, step450 파일, step750 파일, 외부 벤치인가)
SPLITS = [
    ("primevul_report",    "v3s42_450_logprob_primevul_report",
                           "v3s42_logprob_primevul_report",    True),
    ("cleanvul_v2_report", "v3s42_450_logprob_cleanvul_v2_report",
                           "v3s42_logprob_cleanvul_v2_report", True),
    ("test",               "v3s42_450_logprob_test",
                           "v3s42_logprob_test",               False),
]


def load(name: str) -> list[dict]:
    p = ROOT / "out" / f"{name}.jsonl"
    if not p.exists():
        raise SystemExit(f"없는 파일: {p}")
    return [json.loads(l) for l in p.open()]


def align(a: list[dict], b: list[dict], tag: str) -> None:
    if len(a) != len(b):
        raise SystemExit(f"[{tag}] 항목 수 불일치 A={len(a)} B={len(b)} — 폐기")
    for i, (x, y) in enumerate(zip(a, b)):
        if x["meta"].get("label") != y["meta"].get("label"):
            raise SystemExit(f"[{tag}] {i}행 meta.label 불일치 — 폐기")
        if x["meta"].get("pair_id") != y["meta"].get("pair_id"):
            raise SystemExit(f"[{tag}] {i}행 meta.pair_id 불일치 — 폐기")


def paired_bootstrap(a: list[dict], b: list[dict]) -> dict:
    """pair_id 단위 재표집(없으면 항목 단위). 같은 인덱스를 A·B 에 동시 적용."""
    groups: dict[str, list[int]] = {}
    for i, r in enumerate(a):
        groups.setdefault(r["meta"].get("pair_id") or f"_solo{i}", []).append(i)
    keys = list(groups)
    rng = random.Random(SEED)
    deltas = []
    for _ in range(N_BOOT):
        idx = [i for k in (rng.choice(keys) for _ in keys) for i in groups[k]]
        ra, rb = [a[i] for i in idx], [b[i] for i in idx]
        if len({r["meta"]["label"] for r in ra}) < 2:
            continue
        deltas.append(auc(rb) - auc(ra))
    deltas.sort()
    return {"n_boot_used": len(deltas),
            "ci_lo": round(deltas[int(0.025 * len(deltas))], 4),
            "ci_hi": round(deltas[int(0.975 * len(deltas)) - 1], 4),
            "n_resample_units": len(keys),
            "unit": "pair_id" if any(not k.startswith("_solo") for k in keys) else "item"}


def run(name: str, f450: str, f750: str) -> dict:
    a, b = load(f450), load(f750)
    align(a, b, name)
    auc_a, auc_b = auc(a), auc(b)
    delta = round(auc_b - auc_a, 4)
    boot = paired_bootstrap(a, b)
    res = {"split": name, "n": len(a),
           "auc_step450": auc_a, "auc_step750": auc_b, "delta_auc": delta, **boot}
    res["improves"] = bool(delta > 0 and boot["ci_lo"] > 0)
    # 사양서 §6 — 결과 보기 전에 고정한 선형 외삽 (낙관적 상한)
    extrap = auc_b + delta * (TOTAL_STEPS - STEP_B) / (STEP_B - STEP_A)
    res["linear_extrapolation_to_step_1674"] = round(extrap, 4)
    res["extrap_reaches_target_0_75"] = bool(extrap >= TARGET_AUC)
    return res


def main() -> None:
    results = {name: run(name, f4, f7) for name, f4, f7, _ in SPLITS}

    sanity = {}
    for name, target in SANITY.items():
        obs = results[name]["auc_step750"]
        sanity[name] = {"target": target, "observed": obs,
                        "passed": abs(obs - target) <= SANITY_TOL}
    sanity_ok = all(v["passed"] for v in sanity.values())

    ext = [n for n, _, _, is_ext in SPLITS if is_ext]
    n_improve = sum(results[n]["improves"] for n in ext)
    gate = ("DOSE-RESPONSE-REAL" if n_improve == 2 else
            "DOSE-RESPONSE-WEAK" if n_improve == 1 else "DOSE-RESPONSE-NULL")

    out = {"spec": "rebuild/DOSE_RUN_SPEC.md", "seed": SEED, "n_boot": N_BOOT,
           "steps_compared": [STEP_A, STEP_B], "total_planned_steps": TOTAL_STEPS,
           "sanity_check": {"tol": SANITY_TOL, "splits": sanity, "passed": sanity_ok},
           "splits": results,
           "external_splits": ext, "n_external_improving": n_improve}
    if not sanity_ok:
        out["ABORT"] = ("건전성 검사 실패 — 사양서 §4에 따라 결과를 해석하지 않는다.")
    else:
        out["FINAL_VERDICT"] = gate
    (ROOT / "out" / "dose_metrics.json").write_text(
        json.dumps(out, ensure_ascii=False, indent=2))
    print(json.dumps(out, ensure_ascii=False, indent=2))


if __name__ == "__main__":
    main()
