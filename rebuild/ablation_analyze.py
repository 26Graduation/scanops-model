"""
Ablation Phase 2·3 — arm 정의 / 지표 산출 / 부트스트랩 CI
=========================================================
ablation_graph_only.py가 남긴 raw JSONL만 읽어 **후처리 산술로만** arm 4개를
만든다. graph 재계산·LLM 재채점 없음.

arm (사전 등록, 사후 변경 없음):
  (a) LLM + graph        = [llm_score >= τ] OR [graph_verdict == "vuln"]
  (b) LLM만              = [llm_score >= τ]
  (c) graph만            = [graph_verdict == "vuln"]
  (d) 무조건 VULNERABLE  = 항상 vuln

unknown 처리: 주 규약 unknown → safe / 부 규약 unknown → vuln. 둘 다 병기.

τ (사양 추가 ②):
  tune split의 **graph 지원 언어 부분집합(468건)에서만** 선정한다. 전체 676건에서
  고르면 report 평가 모집단(1,878건)과 언어 구성이 달라져 운영점이 어긋난다.
  pooled 468건에서 **단 하나만** 고르고, 그 공통 τ에서 언어별 지표를 본다
  (언어별 τ는 표본 51~111쌍이라 과적합).
  arm(a)/arm(b)는 각각 자기 최적점을 갖는다(공정 비교).
  기준 ① F1 최대  ② FPR <= 0.35 제약 하 F1 최대.

δ (arm(a) 연속 점수 score_a = llm_score + δ·1[graph=="vuln"]):
  {0.5, 1.0, 2.0} 중 tune 지원 부분집합 AUC 최대값으로 고정.

게이트 (사양 추가 ①③):
  - 언어별 unknown 비율 > 0.70 → 그 언어는 "graph가 판정을 거의 하지 않음"으로
    별도 기록하고 GO/KILL 판정 대상에서 제외.
  - 언어별 ΔRecall(c−a) 부트스트랩 95% CI가 +0.05와 −0.15를 동시에 포함하면
    INCONCLUSIVE(표본 부족)로 기록.

모델 (사양 추가 ④): 주 판정 v1, 재확인 v3s42. 판정 칸이 다르면 총합 판정 금지.

판정 대상 = CleanVul_v2의 graph 지원 언어 부분집합(Java/Python/JavaScript).
C/C++는 _lang_key()가 None → "N/A"로 명시하고 판정에서 제외.

실행: python rebuild/ablation_analyze.py
출력: out/ablation_metrics.json
"""
from __future__ import annotations

import json
import random
import sys
from collections import defaultdict
from pathlib import Path

ROOT = Path(__file__).resolve().parent
sys.path.insert(0, str(ROOT))          # bench_common / sweep_threshold / bootstrap_ci 재사용

from bench_common import pairwise_score, score          # noqa: E402
from bootstrap_ci import units                          # noqa: E402
from sweep_threshold import auc, trivial_baseline       # noqa: E402

OUT = ROOT / "out"
ARMS = ["a", "b", "c", "d"]
ARM_NAME = {
    "a": "LLM + graph (현행 하이브리드)",
    "b": "LLM만 (Graph Off)",
    "c": "graph만 (LLM Off)",
    "d": "무조건 VULNERABLE (자명 기준선)",
}
LANGS = ["Java", "Python", "JavaScript"]
GRAPH_MODULE = {"Java": "java_graph.py", "Python": "multi_graph.py", "JavaScript": "multi_graph.py"}
DELTAS = [0.5, 1.0, 2.0]
FPR_CAP = 0.35
UNKNOWN_ABSTAIN_CAP = 0.70          # 사양 추가 ①
CI_GATE = (0.05, -0.15)             # 사양 추가 ③
MODELS = {"v1": "llm_score", "v3s42": "llm_score_v3s42"}


# ── 로딩 / 서브셋 ────────────────────────────────────────────────────────────
def load_raw(split: str) -> list[dict]:
    return [json.loads(l) for l in (OUT / f"ablation_raw_cleanvul_v2_{split}.jsonl").open()]


def supported(rows: list[dict]) -> list[dict]:
    """graph 지원 언어(Java/Python/JavaScript)만. C/C++는 원리적으로 측정 불가."""
    return [r for r in rows if r["graph_supported"]]


def graph_says_vuln(r: dict, unknown_as_vuln: bool) -> bool:
    if r["graph_verdict"] == "vuln":
        return True
    return unknown_as_vuln and r["graph_verdict"] == "unknown"


def meta_of(r: dict) -> dict:
    return {"label": r["label"], "pair_id": r["pair_id"], "lang_group": r["lang"]}


# ── 사양 추가 ① : unknown(판정 회피) 비율 — 지표보다 먼저 ────────────────────
def abstention_table(rows: list[dict]) -> dict:
    sup = supported(rows)
    out: dict = {"n_supported": len(sup), "by_language": {}, "by_label": {}}
    for L in LANGS:
        s = [r for r in sup if r["lang"] == L]
        if not s:
            continue
        cnt = {v: sum(1 for r in s if r["graph_verdict"] == v) for v in ("vuln", "safe", "unknown")}
        ratio = cnt["unknown"] / len(s)
        out["by_language"][L] = {
            "module": GRAPH_MODULE[L], "n": len(s), **cnt,
            "unknown_ratio": round(ratio, 4),
            "exceeds_abstain_cap": bool(ratio > UNKNOWN_ABSTAIN_CAP),
            "excluded_from_verdict": bool(ratio > UNKNOWN_ABSTAIN_CAP),
        }
    cnt = {v: sum(1 for r in sup if r["graph_verdict"] == v) for v in ("vuln", "safe", "unknown")}
    ratio = cnt["unknown"] / len(sup) if sup else 0.0
    out["overall"] = {"n": len(sup), **cnt, "unknown_ratio": round(ratio, 4),
                      "exceeds_abstain_cap": bool(ratio > UNKNOWN_ABSTAIN_CAP)}
    for lab in ("vuln", "safe"):
        s = [r for r in sup if r["label"] == lab]
        out["by_label"][lab] = {"n": len(s), **{v: sum(1 for r in s if r["graph_verdict"] == v)
                                                for v in ("vuln", "safe", "unknown")}}
    out["n_strong_safe"] = sum(1 for r in sup if r["graph_strong"])
    out["note"] = ("unknown 비율이 상한(0.70)을 넘는 언어는 'graph가 판정을 거의 하지 않음'으로 "
                   "기록하고 GO/KILL 판정 대상에서 제외한다. 전체가 상한을 넘으면 arm(c)의 낮은 "
                   "recall은 오탐 억제가 아니라 판정 회피에서 온 것이다.")
    return out


# ── arm → 예측 / 연속 점수 ──────────────────────────────────────────────────
def predict(rows, arm, tau, unknown_as_vuln, sf="llm_score"):
    out = []
    for r in rows:
        g = graph_says_vuln(r, unknown_as_vuln)
        llm = (r[sf] is not None and tau is not None and r[sf] >= tau)
        pred = (llm or g) if arm == "a" else llm if arm == "b" else g if arm == "c" else True
        out.append({"meta": meta_of(r), "label": "vuln" if pred else "safe"})
    return out


def cont_scores(rows, arm, delta, unknown_as_vuln, sf="llm_score"):
    """연속 점수. arm (c)(d)는 연속 점수가 없다 → None (AUC는 N/A로 적는다)."""
    if arm == "b":
        return [{"meta": meta_of(r), "score": r[sf]} for r in rows]
    if arm == "a":
        return [{"meta": meta_of(r),
                 "score": r[sf] + (delta if graph_says_vuln(r, unknown_as_vuln) else 0.0)}
                for r in rows]
    return None


# ── τ / δ 선정 (tune 지원 부분집합에서만, pooled 단일값) ─────────────────────
def tau_candidates(rows, sf):
    ss = sorted({round(r[sf], 3) for r in rows if r[sf] is not None})
    step = max(1, len(ss) // 200)
    return sorted(set(ss[::step] + [0.0]))


def pick_tau(tune_rows, arm, unknown_as_vuln, sf):
    curve = []
    for t in tau_candidates(tune_rows, sf):
        s = score(predict(tune_rows, arm, t, unknown_as_vuln, sf))
        s["tau"] = t
        curve.append(s)
    best = max(curve, key=lambda x: x["f1"])
    capped = [x for x in curve if x["fpr"] <= FPR_CAP] or curve
    bc = max(capped, key=lambda x: x["f1"])
    return {"tau_f1max": best["tau"], "tune_at_f1max": best,
            "tau_fpr35": bc["tau"], "tune_at_fpr35": bc,
            "n_tune_used": len(tune_rows)}


def pick_delta(tune_rows, unknown_as_vuln, sf):
    aucs = {str(d): auc(cont_scores(tune_rows, "a", d, unknown_as_vuln, sf)) for d in DELTAS}
    best = max(DELTAS, key=lambda d: aucs[str(d)])
    return {"delta": best, "tune_auc_by_delta": aucs,
            "basis": f"tune split의 graph 지원 부분집합 {len(tune_rows)}건에서 AUC 최대"}


# ── pair rank (연속 점수 기반, 동점 규약 2종 병기) ───────────────────────────
def pair_rank(recs):
    g = defaultdict(dict)
    for r in recs:
        g[r["meta"]["pair_id"]][r["meta"]["label"]] = r["score"]
    n = strict = ties = 0
    for d in g.values():
        if set(d) != {"vuln", "safe"}:
            continue
        n += 1
        if d["vuln"] > d["safe"]:
            strict += 1
        elif d["vuln"] == d["safe"]:
            ties += 1
    return {"n_pairs": n, "n_ties": ties,
            "strict": round(strict / n, 4) if n else 0.0,
            "tie_half": round((strict + 0.5 * ties) / n, 4) if n else 0.0}


def arm_metrics(rows, arm, tau, delta, unknown_as_vuln, sf):
    preds = predict(rows, arm, tau, unknown_as_vuln, sf)
    m = score(preds)
    m["pair"] = pairwise_score(preds)
    recs = cont_scores(rows, arm, delta, unknown_as_vuln, sf)
    if recs is None:
        m["auc"] = "N/A"          # 연속 점수 없음 — 0/1로 억지 AUC를 만들지 않는다
        m["pair_rank"] = "N/A"
    else:
        m["auc"] = auc(recs)
        m["pair_rank"] = pair_rank(recs)
    m["tau"] = tau
    return m


def by_language(rows, arm, tau, delta, unknown_as_vuln, sf):
    out = {}
    for L in LANGS:
        sub = [r for r in rows if r["lang"] == L]
        if sub:
            out[L] = arm_metrics(sub, arm, tau, delta, unknown_as_vuln, sf)
    return out


# ── 부트스트랩 (쌍 단위 재표집 2,000회) — bootstrap_ci.units 재사용 ──────────
def paired_boot(rows, armX, armY, tauX, tauY, delta, unknown_as_vuln, sf,
                n=2000, seed=0):
    px = predict(rows, armX, tauX, unknown_as_vuln, sf)
    py = predict(rows, armY, tauY, unknown_as_vuln, sf)
    sx = cont_scores(rows, armX, delta, unknown_as_vuln, sf)
    sy = cont_scores(rows, armY, delta, unknown_as_vuln, sf)
    ux, uy = units(px), units(py)
    assert len(ux) == len(uy), "두 arm의 쌍 수가 다르다"
    order = [u[0]["meta"]["pair_id"] for u in ux]

    def sunits(recs):
        if recs is None:
            return None
        g = defaultdict(list)
        for r in recs:
            g[r["meta"]["pair_id"]].append(r)
        return [g[k] for k in order]

    gx, gy = sunits(sx), sunits(sy)
    rng = random.Random(seed)
    d_f1, d_rec, d_fpr, d_auc = [], [], [], []
    for _ in range(n):
        idx = [rng.randrange(len(ux)) for _ in range(len(ux))]
        a = score([x for i in idx for x in ux[i]])
        b = score([x for i in idx for x in uy[i]])
        d_f1.append(a["f1"] - b["f1"])
        d_rec.append(a["recall"] - b["recall"])
        d_fpr.append(a["fpr"] - b["fpr"])
        if gx is not None and gy is not None:
            d_auc.append(auc([x for i in idx for x in gx[i]]) - auc([x for i in idx for x in gy[i]]))

    def ci(v):
        if not v:
            return None
        v = sorted(v)
        lo, hi = v[int(n * 0.025)], v[int(n * 0.975)]
        return {"ci95": [round(lo, 4), round(hi, 4)], "excludes_zero": bool(lo > 0 or hi < 0)}

    oa, ob = score(px), score(py)
    res = {"compare": f"{armX} - {armY}", "n_pairs": len(ux),
           "delta_recall": round(oa["recall"] - ob["recall"], 4), "recall": ci(d_rec),
           "delta_f1": round(oa["f1"] - ob["f1"], 4), "f1": ci(d_f1),
           "delta_fpr": round(oa["fpr"] - ob["fpr"], 4), "fpr": ci(d_fpr)}
    if sx is not None and sy is not None:
        res["delta_auc"] = round(auc(sx) - auc(sy), 4)
        res["auc"] = ci(d_auc)
    else:
        res["delta_auc"] = "N/A"
        res["auc"] = "N/A"
    return res


# ── 사전 등록 판정표 + 추가 게이트 ──────────────────────────────────────────
def prereg_verdict(rec_c, fpr_c, rec_a, fpr_a):
    loss = rec_a - rec_c
    if loss < 0.05 and fpr_c <= fpr_a:
        return "GO"
    if 0.05 <= loss <= 0.15:
        return "WEAK"
    if loss >= 0.15:
        return "KILL"
    return "INCONCLUSIVE"     # 손실 < 0.05 인데 FPR이 악화된 경우 등


def gated_verdict(rec_c, fpr_c, rec_a, fpr_a, abstain_excluded, ci_recall):
    """게이트 우선순위: ① 판정 회피(unknown>0.70) → ③ CI 폭 → 사전 등록표."""
    base = prereg_verdict(rec_c, fpr_c, rec_a, fpr_a)
    if abstain_excluded:
        return {"verdict": "EXCLUDED(판정 회피: unknown>0.70)", "prereg_would_be": base,
                "gate": "abstain"}
    if ci_recall:
        lo, hi = ci_recall["ci95"]
        if lo <= CI_GATE[1] and hi >= CI_GATE[0]:
            return {"verdict": "INCONCLUSIVE(표본 부족)", "prereg_would_be": base, "gate": "ci_width"}
    return {"verdict": base, "prereg_would_be": base, "gate": None}


# ── 모델 1개에 대한 전체 파이프라인 ─────────────────────────────────────────
def run_model(sup_report, sup_tune, model, sf):
    blk: dict = {"model": model, "score_field": sf, "conventions": {}}
    for conv_name, unk_vuln in (("unknown_as_safe(주)", False), ("unknown_as_vuln(부)", True)):
        cb: dict = {}
        d = pick_delta(sup_tune, unk_vuln, sf)
        cb["delta_selection"] = d
        delta = d["delta"]
        taus = {arm: pick_tau(sup_tune, arm, unk_vuln, sf) for arm in ("a", "b")}
        cb["tau_selection"] = taus

        for crit, key in (("f1max", "tau_f1max"), ("fpr35", "tau_fpr35")):
            arms_out = {}
            for arm in ARMS:
                tau = taus[arm][key] if arm in taus else None
                arms_out[arm] = {
                    "name": ARM_NAME[arm],
                    "report_overall": arm_metrics(sup_report, arm, tau, delta, unk_vuln, sf),
                    "report_by_language": by_language(sup_report, arm, tau, delta, unk_vuln, sf),
                    "tune_overall": arm_metrics(sup_tune, arm, tau, delta, unk_vuln, sf),
                }
            cb[f"tau_{crit}"] = arms_out

            if crit != "fpr35":
                continue

            # 부트스트랩 (전체 + 언어별 c−a)
            boots = []
            for x, y in (("c", "a"), ("b", "a"), ("c", "b"), ("a", "d"), ("b", "d"), ("c", "d")):
                boots.append(paired_boot(sup_report, x, y, taus.get(x, {}).get(key),
                                         taus.get(y, {}).get(key), delta, unk_vuln, sf))
            cb["bootstrap_at_fpr35"] = boots

            lang_boot = {}
            for L in LANGS:
                sub = [r for r in sup_report if r["lang"] == L]
                if sub:
                    lang_boot[L] = paired_boot(sub, "c", "a", taus["c"][key] if "c" in taus else None,
                                               taus["a"][key], delta, unk_vuln, sf)
            cb["bootstrap_c_minus_a_by_language"] = lang_boot

            # 판정
            ab = abstention_table(sup_report)
            ov = {}
            ao = arms_out["a"]["report_overall"]; co = arms_out["c"]["report_overall"]
            ov["overall"] = {
                "recall_a": ao["recall"], "recall_c": co["recall"],
                "fpr_a": ao["fpr"], "fpr_c": co["fpr"],
                "recall_loss": round(ao["recall"] - co["recall"], 4),
                **gated_verdict(co["recall"], co["fpr"], ao["recall"], ao["fpr"],
                                ab["overall"]["exceeds_abstain_cap"],
                                next(b["recall"] for b in boots if b["compare"] == "c - a")),
            }
            for L in LANGS:
                al = arms_out["a"]["report_by_language"].get(L)
                cl = arms_out["c"]["report_by_language"].get(L)
                if not (al and cl):
                    continue
                ov[L] = {
                    "recall_a": al["recall"], "recall_c": cl["recall"],
                    "fpr_a": al["fpr"], "fpr_c": cl["fpr"],
                    "recall_loss": round(al["recall"] - cl["recall"], 4),
                    "unknown_ratio": ab["by_language"][L]["unknown_ratio"],
                    **gated_verdict(cl["recall"], cl["fpr"], al["recall"], al["fpr"],
                                    ab["by_language"][L]["excluded_from_verdict"],
                                    lang_boot[L]["recall"]),
                }
            cb["prereg_verdict_at_fpr35"] = ov
        blk["conventions"][conv_name] = cb

    # unknown 규약 게이트 (arm(c) recall 차이 > 0.10 → 판단 불가)
    rs = blk["conventions"]["unknown_as_safe(주)"]["tau_fpr35"]["c"]["report_overall"]["recall"]
    rv = blk["conventions"]["unknown_as_vuln(부)"]["tau_fpr35"]["c"]["report_overall"]["recall"]
    blk["unknown_convention_gate"] = {
        "recall_c_unknown_as_safe": rs, "recall_c_unknown_as_vuln": rv,
        "abs_diff": round(abs(rv - rs), 4), "threshold": 0.10,
        "triggered": bool(abs(rv - rs) > 0.10),
        "consequence": ("차이가 0.10 초과 → 사전 등록 규칙에 따라 결론은 "
                        "'graph 단독 전환 판단 불가'로 확정"
                        if abs(rv - rs) > 0.10 else "게이트 미발동"),
    }
    return blk


def main() -> None:
    raw = {s: load_raw(s) for s in ("report", "tune")}
    sup = {s: supported(raw[s]) for s in raw}

    result: dict = {
        "scope": {
            "bench": "CleanVul_v2",
            "primary_model": "v1 (rebuild/out/adapter, base unsloth/Qwen3.5-9B) — 캐시 logprob 읽기 전용",
            "secondary_model": "v3s42 (rebuild/out/v3_s42_step750) — 동일 절차 재확인",
            "judgement_subset": "graph 지원 언어(Java/Python/JavaScript)",
            "n_report_total": len(raw["report"]), "n_report_supported": len(sup["report"]),
            "n_tune_total": len(raw["tune"]), "n_tune_supported": len(sup["tune"]),
            "excluded": "C/C++ (multi_graph._lang_key() → None). PrimeVul 전량 C/C++ → 판정 제외",
            "graph_path": ("CleanVul은 단일 함수 스니펫이므로 multi_graph.analyze() 인라인 경로만 "
                           "탄다. code_graph.py(멀티파일 JS/TS)는 이번 실험에서 실행되지 않았다."),
        },
        # 사양 추가 ① — 지표보다 먼저
        "abstention_first": {s: abstention_table(raw[s]) for s in ("report", "tune")},
        "trivial_baseline_report_supported": trivial_baseline(
            [{"meta": meta_of(r), "score": 0.0} for r in sup["report"]]),
        "models": {},
    }
    for model, sf in MODELS.items():
        result["models"][model] = run_model(sup["report"], sup["tune"], model, sf)

    # 사양 추가 ④ — 두 어댑터 판정 칸 비교
    cmp = {}
    for key in ["overall"] + LANGS:
        vs = {m: result["models"][m]["conventions"]["unknown_as_safe(주)"]
                      ["prereg_verdict_at_fpr35"].get(key, {}).get("verdict")
              for m in MODELS}
        cmp[key] = {**vs, "agree": len(set(vs.values())) == 1}
    result["adapter_agreement"] = {
        "verdicts": cmp,
        "all_agree": all(v["agree"] for v in cmp.values()),
        "note": ("두 어댑터의 판정 칸이 다르면 총합 판정을 내지 않고 "
                 "'어댑터에 따라 결론이 뒤집힘'을 §0에 적는다 (V3 §5 시드 민감성 경고)."),
    }

    (OUT / "ablation_metrics.json").write_text(json.dumps(result, ensure_ascii=False, indent=2))
    print(json.dumps({"abstention": result["abstention_first"]["report"]["by_language"],
                      "adapter_agreement": result["adapter_agreement"]["verdicts"],
                      "unknown_gate_v1": result["models"]["v1"]["unknown_convention_gate"]},
                     ensure_ascii=False, indent=2))
    print("saved:", OUT / "ablation_metrics.json")


if __name__ == "__main__":
    main()
