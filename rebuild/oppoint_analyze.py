"""
OPPOINT — 운영점 도달가능성 (사양서 rebuild/OPPOINT_RUN_SPEC.md)
================================================================
질문: 임계값을 옮기면 배포 모델(v1)이 precision 0.70 (사업계획서 "오탐 1/3")에 닿는가.
      닿는다면 recall 을 얼마나 지불하는가.

프로토콜(사양서 §4): τ 는 tune 에서 "precision≥0.70 중 recall 최대"로 고정 선정하고
report 에 1회만 적용한다. report 에서 τ 를 고르지 않는다.

비용 $0 — 기존 산출물만 읽는다.
실행: python3 rebuild/oppoint_analyze.py
출력: out/oppoint_metrics.json
"""
from __future__ import annotations

import json
import random
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent
sys.path.insert(0, str(ROOT))

from bench_common import score            # noqa: E402  — 지표 정의를 재사용
from sweep_threshold import apply_tau, auc  # noqa: E402

SEED = 42
N_BOOT = 2000
PRECISION_TARGET = 0.70   # 사업계획서 "오탐률 1/3"
RECALL_FLOOR = 0.10       # 사양서 §5 — 결과 보기 전에 박은 실용성 바닥선

BASES = [
    ("cleanvul_v2", "v1_logprob_cleanvul_v2_tune", "v1_logprob_cleanvul_v2_report", True),
    ("primevul",    "v1_logprob_primevul_tune",    "v1_logprob_primevul_report",    False),
]


def load(name: str) -> list[dict]:
    p = ROOT / "out" / f"{name}.jsonl"
    if not p.exists():
        raise SystemExit(f"없는 파일: {p}")
    return [json.loads(l) for l in p.open()]


def tau_candidates(recs: list[dict], n: int = 400) -> list[float]:
    xs = sorted({round(r["score"], 4) for r in recs})
    step = max(1, len(xs) // n)
    return sorted(set(xs[::step] + [xs[0] - 1.0, 0.0, xs[-1] + 1.0]))


def curve(recs: list[dict]) -> list[dict]:
    out = []
    for t in tau_candidates(recs):
        s = score(apply_tau(recs, t))
        s["tau"] = t
        out.append(s)
    return out


def trivial(recs: list[dict]) -> dict:
    """자명 기준선 — 전부 vuln 이라 답하는 분류기."""
    return score([{"meta": r["meta"], "label": "vuln"} for r in recs])


def boot_precision_ci(recs: list[dict], tau: float) -> dict:
    """report precision 의 95% CI. pair_id 단위 재표집(없으면 항목 단위)."""
    groups: dict[str, list[int]] = {}
    for i, r in enumerate(recs):
        groups.setdefault(r["meta"].get("pair_id") or f"_solo{i}", []).append(i)
    keys = list(groups)
    rng = random.Random(SEED)
    ps, rs = [], []
    for _ in range(N_BOOT):
        idx = [i for k in (rng.choice(keys) for _ in keys) for i in groups[k]]
        sub = [recs[i] for i in idx]
        if len({r["meta"]["label"] for r in sub}) < 2:
            continue
        s = score(apply_tau(sub, tau))
        if s["precision"] or s["recall"]:
            ps.append(s["precision"]); rs.append(s["recall"])
    ps.sort(); rs.sort()
    q = lambda a, f: round(a[int(f * len(a))], 4) if a else None  # noqa: E731
    return {"n_boot_used": len(ps),
            "precision_ci": [q(ps, 0.025), q(ps, 0.975)],
            "recall_ci": [q(rs, 0.025), q(rs, 0.975)]}


def run(base: str, tune_f: str, report_f: str) -> dict:
    tune, report = load(tune_f), load(report_f)
    ct = curve(tune)

    # 사양서 §4-2 선정 규칙 — tune precision ≥ 0.70 중 recall 최대
    feasible = [c for c in ct if c["precision"] >= PRECISION_TARGET]
    res: dict = {
        "base": base, "n_tune": len(tune), "n_report": len(report),
        "auc_tune": auc(tune), "auc_report": auc(report),
        "trivial_all_vuln_report": trivial(report),
        "n_tune_taus_meeting_target": len(feasible),
    }
    if not feasible:
        res["verdict"] = "PRECISION-UNREACHABLE-ON-TUNE"
        res["note"] = "tune 곡선 전체에서 precision 0.70 을 만족하는 τ 가 없다."
        res["tune_max_precision"] = max(c["precision"] for c in ct)
        return res

    chosen = max(feasible, key=lambda c: c["recall"])
    rep = score(apply_tau(report, chosen["tau"]))
    res["chosen_tau"] = chosen["tau"]
    res["tune_at_chosen"] = chosen
    res["report_at_chosen"] = rep
    res.update(boot_precision_ci(report, chosen["tau"]))

    # 사양서 §5 게이트 — 결과를 보고 바꾸지 않는다
    if rep["precision"] >= PRECISION_TARGET and rep["recall"] >= RECALL_FLOOR:
        res["verdict"] = "PRECISION-REACHABLE"
    elif rep["precision"] >= PRECISION_TARGET:
        res["verdict"] = "PRECISION-DEGENERATE"
    else:
        res["verdict"] = "PRECISION-UNREACHABLE"

    # 참고용 report 곡선 — 판정에 쓰지 않는다(사후 선택 방지)
    cr = curve(report)
    best_p = max(cr, key=lambda c: c["precision"])
    reach = [c for c in cr if c["precision"] >= PRECISION_TARGET and c["recall"] >= RECALL_FLOOR]
    res["reference_only_report_curve"] = {
        "max_precision_point": best_p,
        "n_report_taus_meeting_both": len(reach),
        "best_recall_among_them": max((c["recall"] for c in reach), default=None),
        "WARNING": "이 블록은 사후 정보다. 판정 근거로 쓰지 않는다(사양서 §4-4).",
    }
    return res


def main() -> None:
    out = {"spec": "rebuild/OPPOINT_RUN_SPEC.md", "model": "v1 (배포 어댑터)",
           "seed": SEED, "n_boot": N_BOOT,
           "precision_target": PRECISION_TARGET, "recall_floor": RECALL_FLOOR,
           "results": {}}
    for base, tf, rf, primary in BASES:
        r = run(base, tf, rf)
        r["is_primary"] = primary
        out["results"][base] = r
    out["FINAL_VERDICT"] = out["results"]["cleanvul_v2"]["verdict"]
    (ROOT / "out" / "oppoint_metrics.json").write_text(
        json.dumps(out, ensure_ascii=False, indent=2))
    print(json.dumps(out, ensure_ascii=False, indent=2))


if __name__ == "__main__":
    main()
