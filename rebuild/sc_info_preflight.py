"""
SC-INFO — self-consistency 정보량 사전검증 (사양서 rebuild/SC_INFO_RUN_SPEC.md)
==============================================================================
질문: k=5 self-consistency의 pair_correct 5배 이득(V3_RESULTS §3-4)이
      (H1) 단일 forward에 없는 판별 정보인가, (H2) 운영점 이동일 뿐인가.

AUROC는 임계값과 무관하므로(sweep_threshold.auc 주석) 운영점 이동만으로는 안 움직인다.
따라서 ΔAUC = AUC(투표수) - AUC(logprob) 의 부호와 CI로 갈린다.

비용 $0 — 기존 산출물만 읽는다. 새 추론 없음.
실행: python3 rebuild/sc_info_preflight.py
출력: out/sc_info_metrics.json
"""
from __future__ import annotations

import json
import random
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent
sys.path.insert(0, str(ROOT))

# AUC는 재구현하지 않는다 — 동점 처리(0.5 크레딧)까지 같아야 채널 비교가 성립한다.
from sweep_threshold import auc  # noqa: E402

SEED = 42
N_BOOT = 2000
SANITY_TARGET = 0.580   # V3_RESULTS.md §3-2 이 보고한 v3 PrimeVul AUC
SANITY_TOL = 0.005      # 사양서 §5 건전성 검사


def load(name: str) -> list[dict]:
    p = ROOT / "out" / f"{name}.jsonl"
    if not p.exists():
        raise SystemExit(f"없는 파일: {p}")
    return [json.loads(l) for l in p.open()]


def align(a: list[dict], b: list[dict]) -> None:
    """사양서 §5 무효화 조건 — 정렬이 어긋나면 숫자를 폐기한다."""
    if len(a) != len(b):
        raise SystemExit(f"항목 수 불일치: A={len(a)} B={len(b)} — 사양서 §5에 따라 폐기")
    for i, (x, y) in enumerate(zip(a, b)):
        for k in ("pair_id", "label"):
            if x["meta"].get(k) != y["meta"].get(k):
                raise SystemExit(f"{i}행 meta.{k} 불일치 — 사양서 §5에 따라 폐기")


def as_scored(recs: list[dict], key: str) -> list[dict]:
    """auc()가 기대하는 모양({'meta':…, 'score':…})으로 바꾼다. gold는 meta.label."""
    return [{"meta": r["meta"], "score": float(r[key])} for r in recs]


def coarsen(recs: list[dict], bins: int = 6) -> list[dict]:
    """사양서 §6 2차 검사 — 연속 점수를 6분위로 이산화해 해상도를 B와 맞춘다."""
    xs = sorted(r["score"] for r in recs)
    cuts = [xs[int(len(xs) * i / bins)] for i in range(1, bins)]
    def b(v: float) -> int:
        return sum(1 for c in cuts if v >= c)
    return [{"meta": r["meta"], "score": float(b(r["score"]))} for r in recs]


def paired_bootstrap(a: list[dict], b: list[dict]) -> dict:
    """meta.pair_id 단위 재표집(V3_RESULTS §2-1 '케이스 재표집' 관례).
    같은 인덱스를 A·B에 동시 적용한다 — paired."""
    groups: dict[str, list[int]] = {}
    for i, r in enumerate(a):
        groups.setdefault(r["meta"].get("pair_id") or f"_solo{i}", []).append(i)
    keys = list(groups)
    rng = random.Random(SEED)
    deltas = []
    for _ in range(N_BOOT):
        idx = [i for k in (rng.choice(keys) for _ in keys) for i in groups[k]]
        ra, rb = [a[i] for i in idx], [b[i] for i in idx]
        # 재표집으로 한쪽 라벨이 사라지면 auc()가 0.0을 뱉으므로 그 표본은 버린다.
        labs = {r["meta"]["label"] for r in ra}
        if len(labs) < 2:
            continue
        deltas.append(auc(rb) - auc(ra))
    deltas.sort()
    lo = deltas[int(0.025 * len(deltas))]
    hi = deltas[int(0.975 * len(deltas)) - 1]
    return {"n_boot_used": len(deltas), "ci_lo": round(lo, 4), "ci_hi": round(hi, 4),
            "n_pairs": len(keys)}


def verdict(delta: float, ci_lo: float, ci_hi: float) -> str:
    """사양서 §5 게이트 — 결과를 보고 바꾸지 않는다."""
    if delta > 0 and ci_lo > 0:
        return "SC-INFO-REAL"
    if delta < 0 and ci_hi < 0:
        return "SC-INFO-WORSE"
    return "SC-THRESHOLD-ONLY"


def run(name: str, lp_file: str, vote_file: str) -> dict:
    lp, vt = load(lp_file), load(vote_file)
    align(lp, vt)
    A = as_scored(lp, "score")
    B = as_scored(vt, "n_vuln_votes")
    auc_a, auc_b = auc(A), auc(B)
    delta = round(auc_b - auc_a, 4)
    boot = paired_bootstrap(A, B)
    res = {
        "split": name, "n": len(A),
        "n_vuln": sum(1 for r in A if r["meta"]["label"] == "vuln"),
        "auc_A_single_forward": auc_a,
        "auc_B_self_consistency": auc_b,
        "delta_auc": delta,
        **boot,
        "verdict": verdict(delta, boot["ci_lo"], boot["ci_hi"]),
    }
    # 사양서 §6 — null 이면 이산화가 설명인지 본다.
    if res["verdict"] == "SC-THRESHOLD-ONLY":
        ac = coarsen(A)
        res["auc_A_coarse_6bin"] = auc(ac)
        res["coarsening_explains_null"] = res["auc_A_coarse_6bin"] < auc_b - 0.02
    # 참고용: 투표수 분포 (판정에 쓰지 않는다)
    res["vote_hist"] = {str(v): sum(1 for r in vt if r["n_vuln_votes"] == v) for v in range(6)}
    return res


def main() -> None:
    primary = run("primevul_report", "v3s42_logprob_primevul_report",
                  "v3s42_primevul_report_votes_k5")

    sanity_ok = abs(primary["auc_A_single_forward"] - SANITY_TARGET) <= SANITY_TOL
    out = {
        "spec": "rebuild/SC_INFO_RUN_SPEC.md",
        "seed": SEED, "n_boot": N_BOOT,
        "sanity_check": {
            "target_auc_from_V3_RESULTS_3_2": SANITY_TARGET, "tol": SANITY_TOL,
            "observed": primary["auc_A_single_forward"], "passed": sanity_ok,
        },
        "primary": primary,
    }
    if not sanity_ok:
        out["ABORT"] = ("건전성 검사 실패 — 사양서 §5에 따라 결과를 해석하지 않는다. "
                        "채널 A가 §3-2의 AUC를 재현하지 못했다.")
    else:
        out["confirmatory"] = run("cleanvul_v2_tune", "v3s42_logprob_cleanvul_v2_tune",
                                  "v3s42_cleanvul_v2_tune_votes_k5")
        out["FINAL_VERDICT"] = primary["verdict"]

    (ROOT / "out" / "sc_info_metrics.json").write_text(
        json.dumps(out, ensure_ascii=False, indent=2))
    print(json.dumps(out, ensure_ascii=False, indent=2))


if __name__ == "__main__":
    main()
