"""
Ablation Phase 0 — 프리플라이트 (읽기 전용)
===========================================
"LLM 탐지기를 빼고 Graph 단독으로 전환해도 되는가"를 재기 전에, 재는 것이
원리적으로 가능한지부터 확인한다. 기존 파일은 한 줄도 건드리지 않는다.

점검 항목:
  0-1  캐시된 LLM logprob 4종 파일 실재 확인
  0-2  cleanvul_v2 report/tune split의 언어·라벨 분포
  0-3  multi_graph._lang_key()로 graph 지원 언어 실측 판정 → 측정 가능 부분집합 크기
  0-4  PrimeVul이 전량 C/C++인지 확인 (맞으면 graph arm 원리적 측정 불가 → 판정 제외)
  0-5  결과를 out/ablation_preflight.json에 기록

실행: python rebuild/ablation_preflight.py
"""
from __future__ import annotations

import json
import sys
from collections import Counter
from pathlib import Path

ROOT = Path(__file__).resolve().parent          # rebuild/
REPO = ROOT.parent                              # scanops-model/
sys.path.insert(0, str(REPO))

from scanops.core.multi_graph import _lang_key  # noqa: E402  (읽기 전용 import)

OUT = ROOT / "out"

# 0-1 대상
CACHE_FILES = [
    "v1_logprob_cleanvul_v2_report.jsonl",
    "v1_logprob_cleanvul_v2_tune.jsonl",
    "v3s42_logprob_cleanvul_v2_report.jsonl",
    "v3s42_logprob_cleanvul_v2_tune.jsonl",
]


def load(p: Path) -> list[dict]:
    return [json.loads(l) for l in p.open()]


def case_id(meta: dict) -> str:
    """벤치 데이터에는 case_id 필드가 없다. (pair_id, label)이 쌍 안에서
    유일하므로 이것을 case_id로 삼는다 — 유일성은 아래에서 실증한다."""
    return f"{meta['pair_id']}|{meta['label']}"


def main() -> None:
    res: dict = {"phase": 0, "pass": True, "failures": []}

    # ── 0-1. 캐시 파일 실재 ───────────────────────────────────────────────
    cache = {}
    for name in CACHE_FILES:
        p = OUT / name
        cache[name] = {"exists": p.exists(), "n": len(p.open().readlines()) if p.exists() else 0}
        if not p.exists():
            res["pass"] = False
            res["failures"].append(f"0-1 캐시 파일 없음: {name}")
    res["0_1_cache_files"] = cache

    # ── 0-2. 언어·라벨 분포 ───────────────────────────────────────────────
    splits = {}
    for split in ("report", "tune"):
        data = load(ROOT / "data" / f"cleanvul_v2_{split}.jsonl")
        ids = [case_id(r["meta"]) for r in data]
        dup = [k for k, v in Counter(ids).items() if v > 1]
        splits[split] = {
            "n": len(data),
            "case_id_unique": not dup,
            "case_id_duplicates": dup[:10],
            "n_pairs": len({r["meta"]["pair_id"] for r in data}),
            "by_language": dict(Counter(r["meta"]["language"] for r in data).most_common()),
            "by_lang_group": dict(Counter(r["meta"]["lang_group"] for r in data).most_common()),
            "by_label": dict(Counter(r["meta"]["label"] for r in data).most_common()),
        }
        if dup:
            res["pass"] = False
            res["failures"].append(f"0-2 {split}: case_id 중복 {len(dup)}건")
    res["0_2_splits"] = splits

    # ── 0-3. graph 지원 언어 실측 (_lang_key가 None이면 미지원) ────────────
    langs = sorted({r["meta"]["language"] for split in ("report", "tune")
                    for r in load(ROOT / "data" / f"cleanvul_v2_{split}.jsonl")})
    lang_key = {L: _lang_key(L) for L in langs}
    supported = sorted(L for L, k in lang_key.items() if k is not None)
    unsupported = sorted(L for L, k in lang_key.items() if k is None)
    res["0_3_lang_key"] = {
        "probe": lang_key,
        "supported": supported,
        "unsupported_returns_None": unsupported,
    }
    # 측정 가능 부분집합 크기
    measurable = {}
    for split in ("report", "tune"):
        data = load(ROOT / "data" / f"cleanvul_v2_{split}.jsonl")
        n_ok = sum(1 for r in data if _lang_key(r["meta"]["language"]) is not None)
        measurable[split] = {
            "n_total": len(data),
            "n_graph_measurable": n_ok,
            "pct": round(100 * n_ok / len(data), 1) if data else 0.0,
            "n_graph_unmeasurable": len(data) - n_ok,
            "by_language_measurable": dict(Counter(
                r["meta"]["language"] for r in data
                if _lang_key(r["meta"]["language"]) is not None).most_common()),
            "by_language_unmeasurable": dict(Counter(
                r["meta"]["language"] for r in data
                if _lang_key(r["meta"]["language"]) is None).most_common()),
        }
    res["0_3_measurable_subset"] = measurable

    # ── 0-4. PrimeVul 언어 확인 (graph arm 측정 가능성) ────────────────────
    pv = {}
    for split in ("report", "tune"):
        p = ROOT / "data" / f"primevul_{split}.jsonl"
        if not p.exists():
            pv[split] = {"exists": False}
            continue
        data = load(p)
        pv[split] = {
            "exists": True, "n": len(data),
            "by_language": dict(Counter(r["meta"]["language"] for r in data).most_common()),
            "n_graph_measurable": sum(1 for r in data
                                      if _lang_key(r["meta"]["language"]) is not None),
        }
    res["0_4_primevul"] = pv
    res["0_4_verdict"] = ("PrimeVul은 graph 미지원 언어 전량 → graph arm 측정 불가. 판정 대상에서 제외"
                          if all(v.get("n_graph_measurable", 0) == 0 for v in pv.values() if v.get("exists"))
                          else "PrimeVul에 graph 측정 가능 건이 존재 — 사양 가정과 불일치, 확인 필요")

    # ── case_id 정합성: 벤치 데이터 ↔ 캐시 logprob ─────────────────────────
    match = {}
    for tag in ("v1", "v3s42"):
        for split in ("report", "tune"):
            bench = {case_id(r["meta"]) for r in load(ROOT / "data" / f"cleanvul_v2_{split}.jsonl")}
            lp_path = OUT / f"{tag}_logprob_cleanvul_v2_{split}.jsonl"
            if not lp_path.exists():
                continue
            lp_recs = load(lp_path)
            lp_ids = [case_id(r["meta"]) for r in lp_recs]
            lp_set = set(lp_ids)
            missing = sorted(bench - lp_set)
            extra = sorted(lp_set - bench)
            match[f"{tag}_{split}"] = {
                "n_bench": len(bench), "n_logprob": len(lp_recs),
                "n_logprob_unique": len(lp_set),
                "n_matched": len(bench & lp_set),
                "n_missing_in_logprob": len(missing), "missing_sample": missing[:5],
                "n_extra_in_logprob": len(extra), "extra_sample": extra[:5],
                "has_score_field": all("score" in r for r in lp_recs),
            }
            if missing or extra:
                res["pass"] = False
                res["failures"].append(
                    f"case_id 매칭 실패 {tag}/{split}: missing {len(missing)}, extra {len(extra)}")
    res["0_case_id_match"] = match

    OUT.mkdir(exist_ok=True)
    (OUT / "ablation_preflight.json").write_text(
        json.dumps(res, ensure_ascii=False, indent=2))
    print(json.dumps(res, ensure_ascii=False, indent=2))
    print("\nPREFLIGHT:", "PASS" if res["pass"] else "FAIL")


if __name__ == "__main__":
    main()
