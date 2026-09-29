"""
Ablation §8-6 — 조건 ① 선행 절차: CWE 라벨 보유 벤치에서 적용 범위 측정
=======================================================================
§8-5가 요구한 "CWE 라벨이 있는 벤치에서 조건 ①(taint 계열 CWE 비중)을 실제로
재는 절차". CPU 후처리 + multi_graph.analyze() 호출만. LLM 추론·GPU 없음.
기존 파일 무수정 — 이 스크립트와 out/ablation_coverage_* 산출물만 추가.

대상:
  data/cvefixes_benchmark.jsonl  (157건, cwe 필드 보유 — 조건 ① 실측용)
  data/owasp_holdout_bench.jsonl (110건, @WebServlet 경로에서 카테고리 추출 —
                                  (B) 규칙 부족 가설의 반증용)

사전 등록 판정:
  - OWASP에서 graph unknown 비율 > 0.50 → "(B) 규칙 부족" 채택
  - CVEfixes taint 계열 CWE 비중 < 0.30 → "(A) 벤치 불일치" 채택
  - 둘 다 성립하면 둘 다 적는다(배타적이지 않다).
  - OWASP 결과는 multi_graph.py/java_graph.py가 OWASP 형태를 알고 설계된
    자산이므로(과적합 경고) (B)의 반증 용도로만 쓴다.

실행: python rebuild/ablation_coverage_bench.py
출력: out/ablation_coverage_raw_{cvefixes,owasp}.jsonl, out/ablation_coverage_bench.json
"""
from __future__ import annotations

import json
import re
import sys
from collections import Counter, defaultdict
from pathlib import Path

ROOT = Path(__file__).resolve().parent
REPO = ROOT.parent
sys.path.insert(0, str(REPO))

from scanops.core.multi_graph import _CWE, _lang_key, analyze  # noqa: E402 (읽기 전용)

OUT = ROOT / "out"

# multi_graph._CWE 11종 → CWE 번호 (§8-2와 동일 추출)
CAT_CWE = {cat: int(re.match(r"CWE-(\d+)", label).group(1)) for cat, label in _CWE.items()}
TAINT7 = {"sqli", "cmdi", "xss", "pathtraver", "ssrf", "deser", "codei"}
PRIM4 = {"crypto", "hash", "weakrand", "secret"}
TAINT7_CWE = {CAT_CWE[c] for c in TAINT7}          # {89,78,79,22,918,502,94}
ALL11_CWE = set(CAT_CWE.values())

# OWASP @WebServlet 경로 → 카테고리 (예: "/pathtraver-00/BenchmarkTest00001")
OWASP_URL = re.compile(r'@WebServlet\(\s*value\s*=\s*"([^"]+)"')
# OWASP 11개 카테고리 중 taint 계열(사용자입력→sink 추적이 필요한 것)
OWASP_TAINT = {"cmdi", "sqli", "pathtraver", "xss", "ldapi", "xpathi", "trustbound"}
OWASP_NONTAINT = {"crypto", "hash", "weakrand", "securecookie"}


def classify_unknown(reason: str) -> tuple[str, str]:
    """§8-4와 동일한 코드 경로 분류."""
    if reason == "미지원 언어 → LLM 위임":
        return ("언어키 None", "multi_graph.py:173")
    if reason == "위험 sink 미검출 → LLM 위임":
        return ("sink 미발견", "multi_graph.py:229")
    if re.match(r".* sink 존재하나 source 흐름 판정 불가", reason):
        return ("source 미발견", "multi_graph.py:223")
    if reason.startswith("약한 해시지만 용도 불명"):
        return ("용도 미결정(해시)", "multi_graph.py:185")
    if reason.startswith("난수지만 보안 용도 불명"):
        return ("용도 미결정(난수)", "multi_graph.py:189")
    if reason == "카테고리/판정 불가":
        return ("카테고리 미결정", "java_graph.py:415")
    if reason == "taint 흐름 판정 불가 → LLM 위임":
        return ("흐름 미해결(source는 있음)", "java_graph.py:433")
    if "외부설정 유래" in reason:
        return ("외부설정 유래", "java_graph.py:368/380")
    return ("미분류", "?")


def load(p: str) -> list[dict]:
    return [json.loads(l) for l in (REPO / p).open()]


def owasp_category(code: str) -> str | None:
    m = OWASP_URL.search(code)
    if not m:
        return None
    return m.group(1).strip("/").split("/")[0].rsplit("-", 1)[0]


def run_graph(rows: list[dict], bench: str) -> list[dict]:
    """전건에 graph 1회씩. raw를 파일로 남긴다."""
    out_path = OUT / f"ablation_coverage_raw_{bench}.jsonl"
    raws = []
    with out_path.open("w") as f:
        for i, r in enumerate(rows):
            g = analyze(r["code"], r["language"])
            row = {
                "bench": bench, "idx": i,
                "lang": r["language"], "label": r["label"],
                "cwe": r.get("cwe", ""),
                "owasp_category": owasp_category(r["code"]) if bench == "owasp" else None,
                "graph_supported": _lang_key(r["language"]) is not None,
                "graph_verdict": g["verdict"],
                "graph_category": g.get("category", ""),
                "graph_reason": g.get("reason", ""),
            }
            f.write(json.dumps(row, ensure_ascii=False) + "\n")
            raws.append(row)
    return raws


def verdict_table(raws: list[dict]) -> dict:
    """언어별 × verdict 교차표 + unknown 사유(코드 경로) 분류."""
    langs = sorted({r["lang"] for r in raws})
    tab = {}
    for L in langs:
        s = [r for r in raws if r["lang"] == L]
        tab[L] = {
            "n": len(s), "graph_supported": s[0]["graph_supported"],
            **{v: sum(1 for r in s if r["graph_verdict"] == v) for v in ("vuln", "safe", "unknown")},
        }
        tab[L]["unknown_ratio"] = round(tab[L]["unknown"] / len(s), 4)
    total = {v: sum(1 for r in raws if r["graph_verdict"] == v) for v in ("vuln", "safe", "unknown")}
    reasons = defaultdict(Counter)
    for r in raws:
        if r["graph_verdict"] == "unknown":
            cat, loc = classify_unknown(r["graph_reason"])
            reasons[f"{cat} ({loc})"][r["lang"]] += 1
    return {"by_language": tab,
            "total": {**total, "n": len(raws),
                      "unknown_ratio": round(total["unknown"] / len(raws), 4)},
            "unknown_reasons": {k: dict(v) for k, v in
                                sorted(reasons.items(), key=lambda kv: -sum(kv[1].values()))}}


def main() -> None:
    res: dict = {"cat_cwe_11": {c: f"CWE-{n}" for c, n in CAT_CWE.items()},
                 "taint7_cwe": sorted(TAINT7_CWE), "all11_cwe": sorted(ALL11_CWE)}

    # ── (1)+(2) CVEfixes: 메타 확정 + CWE 분포 + 교집합 비율 ─────────────────
    cf = load("data/cvefixes_benchmark.jsonl")
    vuln = [r for r in cf if r["label"] == "vuln"]
    cwe_dist = Counter(r["cwe"] for r in vuln)

    def cwe_num(s: str) -> int | None:
        m = re.fullmatch(r"CWE-(\d+)", s or "")
        return int(m.group(1)) if m else None      # NVD-CWE-noinfo/Other → None

    informative = [r for r in vuln if cwe_num(r["cwe"]) is not None]
    in_taint7 = [r for r in informative if cwe_num(r["cwe"]) in TAINT7_CWE]
    in_all11 = [r for r in informative if cwe_num(r["cwe"]) in ALL11_CWE]
    res["cvefixes"] = {
        "meta_fields": sorted({k for r in cf for k in r}),
        "cwe_field": "cwe (톱레벨) — 실재 확인",
        "n": len(cf), "n_vuln": len(vuln),
        "cwe_distribution_vuln": dict(cwe_dist.most_common()),
        "n_noinfo": sum(v for k, v in cwe_dist.items() if not k.startswith("CWE-")),
        "n_informative": len(informative),
        "intersection": {
            "taint7_hits": sorted(Counter(r["cwe"] for r in in_taint7).items()),
            "all11_hits": sorted(Counter(r["cwe"] for r in in_all11).items()),
            "taint7_over_all_vuln": {"n": len(in_taint7), "d": len(vuln),
                                     "ratio": round(len(in_taint7) / len(vuln), 4)},
            "taint7_over_informative": {"n": len(in_taint7), "d": len(informative),
                                        "ratio": round(len(in_taint7) / len(informative), 4)},
            "all11_over_all_vuln": {"n": len(in_all11), "d": len(vuln),
                                    "ratio": round(len(in_all11) / len(vuln), 4)},
            "all11_over_informative": {"n": len(in_all11), "d": len(informative),
                                       "ratio": round(len(in_all11) / len(informative), 4)},
        },
    }

    # ── (1) OWASP: 카테고리 추출 ────────────────────────────────────────────
    ow = load("data/owasp_holdout_bench.jsonl")
    cats = [owasp_category(r["code"]) for r in ow]
    res["owasp"] = {
        "meta_fields": sorted({k for r in ow for k in r}),
        "cwe_field": "없음 — @WebServlet 경로에서 카테고리 추출 (110/110 성공)",
        "n": len(ow), "n_extract_fail": sum(1 for c in cats if c is None),
        "category_distribution": dict(Counter(c for c in cats if c).most_common()),
        "taint_categories": sorted(OWASP_TAINT), "nontaint_categories": sorted(OWASP_NONTAINT),
    }

    # ── (3) graph 전건 실행 ────────────────────────────────────────────────
    cf_raw = run_graph(cf, "cvefixes")
    ow_raw = run_graph(ow, "owasp")
    res["cvefixes"]["graph"] = verdict_table(cf_raw)
    res["owasp"]["graph"] = verdict_table(ow_raw)

    # OWASP: taint 부분집합의 unknown 비율 (판정 조건은 "전량 taint" 전제였으므로
    # 전제 검증을 위해 전체와 taint 부분집합을 모두 계산)
    ow_taint = [r for r in ow_raw if r["owasp_category"] in OWASP_TAINT]
    res["owasp"]["graph_taint_subset"] = verdict_table(ow_taint)
    # OWASP 카테고리별 × verdict
    bycat = {}
    for c in sorted({r["owasp_category"] for r in ow_raw}):
        s = [r for r in ow_raw if r["owasp_category"] == c]
        bycat[c] = {v: sum(1 for r in s if r["graph_verdict"] == v)
                    for v in ("vuln", "safe", "unknown")}
        bycat[c]["n"] = len(s)
        bycat[c]["correct"] = sum(1 for r in s if r["graph_verdict"] == r["label"])
    res["owasp"]["graph_by_category"] = bycat

    # ── (4) 사전 등록 판정 ─────────────────────────────────────────────────
    ow_unknown = res["owasp"]["graph"]["total"]["unknown_ratio"]
    ow_taint_unknown = res["owasp"]["graph_taint_subset"]["total"]["unknown_ratio"]
    cf_ratio_all = res["cvefixes"]["intersection"]["taint7_over_all_vuln"]["ratio"]
    cf_ratio_inf = res["cvefixes"]["intersection"]["taint7_over_informative"]["ratio"]
    res["prereg_verdict"] = {
        "B_rule_deficit": {
            "condition": "OWASP graph unknown 비율 > 0.50",
            "measured_overall": ow_unknown, "measured_taint_subset": ow_taint_unknown,
            "holds": bool(ow_unknown > 0.50),
            "caveat": ("OWASP는 java_graph가 그 형태를 알고 설계된 자산(과적합 경고)이므로 "
                       "이 결과는 (B)의 반증 용도로만 쓰고 graph 성능 근거로 인용하지 않는다"),
        },
        "A_bench_mismatch": {
            "condition": "CVEfixes taint 계열 CWE 비중 < 0.30",
            "measured_over_all_vuln": cf_ratio_all,
            "measured_over_informative": cf_ratio_inf,
            "holds_over_all_vuln": bool(cf_ratio_all < 0.30),
            "holds_over_informative": bool(cf_ratio_inf < 0.30),
        },
    }

    (OUT / "ablation_coverage_bench.json").write_text(
        json.dumps(res, ensure_ascii=False, indent=2))
    print(json.dumps(res["prereg_verdict"], ensure_ascii=False, indent=2))
    print("saved:", OUT / "ablation_coverage_bench.json")


if __name__ == "__main__":
    main()
