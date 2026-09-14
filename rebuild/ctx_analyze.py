"""
CTX-1 — arm 비교 분석 (사양서 §4·§5)
====================================
입력: out/ctx_{arm}_logprob_primevul_{report,tune}.jsonl  (4 arm × 2 split)
출력: out/ctx_metrics.json  (표·판정에 쓰는 모든 숫자)

무결성 규칙 이행:
  §4-2  주 지표는 AUC와 pair_rank_correct. F1은 부가. 모든 표에 자명 기준선 병기.
  §4-5  arm 간 비교는 동일 케이스 부분집합에서만 (교집합을 강제로 취한다).
  §4-6  성공 부분집합 T0 AUC vs 전체 288건 T0(=v1) AUC 비교 → 표본 편향 경고 판정.
  §4-7  임계값 τ는 tune split에서만 고른다.
  §4-8  ΔAUC는 부트스트랩 2,000회 CI와 함께 보고. 쌍 단위 재표집(bootstrap_ci.units).

실행: python rebuild/ctx_analyze.py
"""
from __future__ import annotations

import json
import random
from collections import defaultdict
from pathlib import Path

from bootstrap_ci import units          # 쌍 단위 재표집 — v3 스크립트 재사용

ROOT = Path(__file__).resolve().parent
OUT = ROOT / "out"
ARMS = ["T0", "T1", "T1shuf", "T1nofunc"]
N_BOOT = 2000


def load(path: Path) -> list[dict]:
    return [json.loads(l) for l in path.open()]


# ── 지표 ────────────────────────────────────────────────────────────────────
def auc(rows: list[dict]) -> float:
    """동점 보정 포함 rank 기반 AUC (Mann-Whitney U)."""
    pos = [r["score"] for r in rows if r["meta"]["label"] == "vuln"]
    neg = [r["score"] for r in rows if r["meta"]["label"] == "safe"]
    if not pos or not neg:
        return float("nan")
    allv = sorted(pos + neg)
    ranks: dict[float, float] = {}
    i = 0
    while i < len(allv):
        j = i
        while j + 1 < len(allv) and allv[j + 1] == allv[i]:
            j += 1
        r = (i + j) / 2 + 1                       # 동점은 평균 순위
        for k in range(i, j + 1):
            ranks[allv[k]] = r
        i = j + 1
    rsum = sum(ranks[v] for v in pos)
    return (rsum - len(pos) * (len(pos) + 1) / 2) / (len(pos) * len(neg))


def pair_rank(rows: list[dict]) -> dict:
    """pair_rank_correct = mean[ score(vuln) > score(patched) ] — 우연 기준선 0.500."""
    g: dict[str, dict[str, float]] = defaultdict(dict)
    for r in rows:
        g[r["meta"]["pair_id"]][r["meta"]["label"]] = r["score"]
    win = tie = n = 0
    for d in g.values():
        if set(d) != {"vuln", "safe"}:
            continue
        n += 1
        if d["vuln"] > d["safe"]:
            win += 1
        elif d["vuln"] == d["safe"]:
            tie += 1
    return {"n_pairs": n, "pair_rank_correct": round(win / n, 4) if n else 0.0,
            "ties": tie,
            "pair_rank_correct_tie_half": round((win + tie / 2) / n, 4) if n else 0.0}


def binary(rows: list[dict], tau: float) -> dict:
    """score > tau 이면 vuln 판정."""
    tp = fp = nv = ns = 0
    for r in rows:
        pred = r["score"] > tau
        if r["meta"]["label"] == "vuln":
            nv += 1
            tp += pred
        else:
            ns += 1
            fp += pred
    rec = tp / nv if nv else 0.0
    fpr = fp / ns if ns else 0.0
    prec = tp / (tp + fp) if (tp + fp) else 0.0
    f1 = 2 * prec * rec / (prec + rec) if (prec + rec) else 0.0
    return {"tau": round(tau, 4), "f1": round(f1, 4), "recall": round(rec, 4),
            "fpr": round(fpr, 4), "precision": round(prec, 4)}


def best_tau(rows: list[dict]) -> float:
    """tune split에서 F1을 최대화하는 τ."""
    cands = sorted({r["score"] for r in rows})
    grid = [c - 1e-6 for c in cands] + [max(cands) + 1.0]
    return max(grid, key=lambda t: binary(rows, t)["f1"])


def boot_delta_auc(a: list[dict], b: list[dict], n: int = N_BOOT, seed: int = 0) -> dict:
    """대응 표본 부트스트랩: 같은 쌍 재표집에 두 arm을 함께 태운다."""
    ua = {tuple(sorted(x["meta"]["pair_id"] for x in u))[0]: u for u in units(a)}
    ub = {tuple(sorted(x["meta"]["pair_id"] for x in u))[0]: u for u in units(b)}
    keys = sorted(set(ua) & set(ub))
    rng = random.Random(seed)
    ds = []
    for _ in range(n):
        idx = [rng.randrange(len(keys)) for _ in range(len(keys))]
        sa = [x for i in idx for x in ua[keys[i]]]
        sb = [x for i in idx for x in ub[keys[i]]]
        ds.append(auc(sa) - auc(sb))
    ds.sort()
    lo, hi = ds[int(n * 0.025)], ds[int(n * 0.975)]
    return {"delta_auc": round(auc(a) - auc(b), 4),
            "ci95": [round(lo, 4), round(hi, 4)],
            "ci_lower_gt_0": bool(lo > 0), "excludes_0": bool(lo > 0 or hi < 0)}


# ── 자명 기준선: 무조건 VULNERABLE ──────────────────────────────────────────
def trivial(rows: list[dict]) -> dict:
    nv = sum(1 for r in rows if r["meta"]["label"] == "vuln")
    ns = len(rows) - nv
    prec, rec = nv / max(1, nv + ns), 1.0
    return {"tau": None, "f1": round(2 * prec * rec / (prec + rec), 4),
            "recall": 1.0, "fpr": 1.0, "precision": round(prec, 4),
            "auc": 0.5, "pair_rank_correct": 0.0}


def main() -> None:
    rep = {a: load(OUT / f"ctx_{a}_logprob_primevul_report.jsonl") for a in ARMS}
    tune = {a: load(OUT / f"ctx_{a}_logprob_primevul_tune.jsonl") for a in ARMS}

    # §4-5 동일 케이스 강제
    common = set.intersection(*[{(r["meta"]["pair_id"], r["meta"]["label"]) for r in rep[a]} for a in ARMS])
    for a in ARMS:
        rep[a] = [r for r in rep[a] if (r["meta"]["pair_id"], r["meta"]["label"]) in common]
    common_t = set.intersection(*[{(r["meta"]["pair_id"], r["meta"]["label"]) for r in tune[a]} for a in ARMS])
    for a in ARMS:
        tune[a] = [r for r in tune[a] if (r["meta"]["pair_id"], r["meta"]["label"]) in common_t]

    res: dict = {"n_common_report": len(common), "n_common_tune": len(common_t), "arms": {}}

    for a in ARMS:
        taus = best_tau(tune[a])                      # §4-7: τ는 tune에서만
        res["arms"][a] = {
            "n": len(rep[a]),
            "auc": round(auc(rep[a]), 4),
            **pair_rank(rep[a]),
            "argmax": binary(rep[a], 0.0),            # 모델의 기본 운영점 (선정 없음)
            "tune_tau_f1max": binary(rep[a], taus),   # tune에서 고른 τ를 report에 적용
            "auc_tune": round(auc(tune[a]), 4),
            "score_mean": round(sum(r["score"] for r in rep[a]) / len(rep[a]), 4),
            "score_std": round((sum((r["score"] - sum(x["score"] for x in rep[a]) / len(rep[a])) ** 2
                                    for r in rep[a]) / len(rep[a])) ** 0.5, 4),
        }
    res["trivial_baseline"] = trivial(rep["T0"])

    # §4-8 ΔAUC 부트스트랩
    res["delta_auc"] = {
        "T1_minus_T0": boot_delta_auc(rep["T1"], rep["T0"]),
        "T1shuf_minus_T0": boot_delta_auc(rep["T1shuf"], rep["T0"]),
        "T1_minus_T1shuf": boot_delta_auc(rep["T1"], rep["T1shuf"]),
        "T1nofunc_minus_T0": boot_delta_auc(rep["T1nofunc"], rep["T0"]),
    }

    # §4-6 표본 편향 점검: 전체 288건에서 잰 v1 T0 AUC vs 우리 부분집합의 T0 AUC
    v1_full = load(OUT / "v1_logprob_primevul_report.jsonl")
    sub_keys = common
    v1_sub = [r for r in v1_full if (r["meta"]["pair_id"], r["meta"]["label"]) in sub_keys]
    res["sample_bias"] = {
        "v1_auc_full_288": round(auc(v1_full), 4), "n_full": len(v1_full),
        "v1_auc_on_kept_subset": round(auc(v1_sub), 4), "n_subset": len(v1_sub),
        "ctx_T0_auc_on_subset": res["arms"]["T0"]["auc"],
        "abs_diff_full_vs_subset": round(abs(auc(v1_full) - auc(v1_sub)), 4),
        "warn": bool(abs(auc(v1_full) - auc(v1_sub)) >= 0.05),
        # T0는 v1과 같은 프롬프트·같은 어댑터이므로 두 값이 일치해야 파이프라인이 정상이다
        "pipeline_reproduces_v1": round(abs(auc(v1_sub) - res["arms"]["T0"]["auc"]), 4),
    }

    # §5 사전 등록 판정표
    t1a, t0a = res["arms"]["T1"]["auc"], res["arms"]["T0"]["auc"]
    shufa = res["arms"]["T1shuf"]["auc"]
    d10 = res["delta_auc"]["T1_minus_T0"]
    gap_shuf = round(t1a - shufa, 4)
    if t1a >= 0.68 and d10["ci_lower_gt_0"] and gap_shuf >= 0.05:
        verdict = "GO"
    elif t1a < t0a and shufa < t0a and abs(t1a - shufa) < 0.05:
        verdict = "FORMAT-SHOCK"
    elif d10["delta_auc"] > 0 and abs((t1a - t0a) - (shufa - t0a)) < 0.05:
        verdict = "ARTIFACT"
    elif 0.62 <= t1a < 0.68 and d10["ci_lower_gt_0"]:
        verdict = "WEAK"
    else:
        verdict = "KILL"
    res["verdict"] = {"cell": verdict, "T1_auc": t1a, "T0_auc": t0a, "T1shuf_auc": shufa,
                      "T1_minus_T1shuf": gap_shuf, "delta_auc_ci": d10["ci95"]}

    (OUT / "ctx_metrics.json").write_text(json.dumps(res, indent=2, ensure_ascii=False))
    print(json.dumps(res, indent=2, ensure_ascii=False))


if __name__ == "__main__":
    main()
