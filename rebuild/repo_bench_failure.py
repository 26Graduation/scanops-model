"""Phase B-5 — 실패 분석.

(1) S2 가 놓친 **cross_file 정답 전부**의 원인 분류
(2) S2 오탐 상위 10건 (정답표 밖 파일을 vuln 으로 판정한 것) — 원문과 함께

원인 분류는 **자동으로 판별 가능한 것만** 라벨을 붙이고, 나머지는 `미분류`로 남긴다.
추측으로 채우지 않는다.

출력: rebuild/out/repo_bench_{repo}_failures.json  (+ 표는 onepager 가 읽는다)
"""
from __future__ import annotations

import json
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent
OUT = ROOT / "out"
DATA = ROOT / "data" / "repo_bench"


def load(p: Path):
    try:
        return json.loads(p.read_text())
    except (OSError, json.JSONDecodeError):
        return None


def load_jsonl(p: Path) -> list[dict]:
    return [json.loads(l) for l in p.open()] if p.exists() else []


def main(repo: str) -> None:
    truth = load_jsonl(DATA / f"{repo}_truth.jsonl")
    inv = load(OUT / f"repo_bench_{repo}_inventory.json")
    s1 = {r["file"]: r for r in load_jsonl(OUT / f"repo_bench_{repo}_s1.jsonl")}
    c1 = {r["file"]: r for r in load_jsonl(OUT / f"repo_bench_{repo}_c1_parity.jsonl")}
    g = load(OUT / f"repo_bench_{repo}_graph.json") or {}
    jo = load(OUT / f"repo_bench_{repo}_joern.json") or {}

    cg_v = set(g.get("code_graph_vuln_files", []))
    mg = g.get("multi_graph_verdicts", {})
    mg_v = set(g.get("multi_graph_vuln_files", []))
    jo_v = set(jo.get("vuln_files", []) or [])
    jo_findings = (jo.get("findings") or {}).get("findings", []) if isinstance(
        jo.get("findings"), dict) else []
    jo_by_base: dict[str, list[dict]] = {}
    for x in jo_findings:
        jo_by_base.setdefault(x["file"], []).append(x)

    in_scope = set(inv["truth_files_in_scope"])
    scored = [t for t in truth if t["sink_file"] in in_scope
              and t["confidence"] in ("high", "med")]
    s2_v = {f for f, r in s1.items() if r["label"] == "vuln"} | cg_v | mg_v | jo_v

    misses = []
    for t in scored:
        if t["sink_file"] in s2_v:
            continue
        f = t["sink_file"]
        base = Path(f).name
        s1r = s1.get(f)
        mgr = mg.get(f, {})
        jof = jo_by_base.get(base, [])
        jo_all_san = bool(jof) and all(x.get("sanitized") for x in jof)
        if s1r is None:
            cause = "미스캔 (스캔 목록에 없거나 실행 중단)"
        elif s1r["label"] == "parse_fail":
            cause = "LLM 파싱 실패"
        elif jo_all_san:
            cause = "Joern: 흐름은 찾았으나 sanitizer 로 제외 (sanitizer 오판 가능)"
        elif jof:
            cause = "Joern: 다른 카테고리 흐름만 잡힘"
        elif f in mg and mgr.get("verdict") == "unknown" and not cg_v:
            cause = ("탐지기 3개 무발화 — LLM safe · multi_graph unknown · "
                     "code_graph sink 패턴 밖 · Joern 흐름 없음")
        else:
            cause = "미분류"
        misses.append({
            "id": t["id"], "sink_file": f, "sink_line": t["sink_line"],
            "cross_file": t["cross_file"], "category": t["category"],
            "challenge_key": t["challenge_key"],
            "s1_label": (s1r or {}).get("label"),
            "multi_graph_verdict": mgr.get("verdict"),
            "code_graph_vuln": f in cg_v,
            "joern_findings_in_file": len(jof),
            "joern_all_sanitized": jo_all_san,
            "cause": cause,
            "line_text": t["line_text"],
        })

    # ── S2 오탐 상위 10 ──────────────────────────────────────────────────────
    truth_files = {t["sink_file"] for t in scored}
    fps = sorted(s2_v - truth_files)
    top = []
    for f in fps:
        srcs = []
        if f in s1 and s1[f]["label"] == "vuln":
            srcs.append(f"LLM:{s1[f].get('cwe') or '?'}")
        if f in mg_v:
            srcs.append(f"multi_graph:{mg.get(f, {}).get('category', '?')}")
        if f in cg_v:
            srcs.append("code_graph")
        if f in jo_v:
            cats = sorted({x["category"] for x in jo_by_base.get(Path(f).name, [])
                           if not x.get("sanitized")})
            srcs.append("joern:" + ",".join(cats[:3]))
        top.append({"file": f, "sources": srcs, "n_sources": len(srcs),
                    "llm_raw": (s1.get(f, {}).get("raws") or [""])[0][:300]})
    top.sort(key=lambda x: -x["n_sources"])

    from collections import Counter
    res = {
        "repo": repo,
        "n_scored": len(scored),
        "n_missed_total": len(misses),
        "n_missed_cross_file": sum(1 for m in misses if m["cross_file"]),
        "cause_counts": dict(Counter(m["cause"] for m in misses)),
        "cause_counts_cross_file": dict(Counter(m["cause"] for m in misses if m["cross_file"])),
        "missed": misses,
        "n_s2_fp_files": len(fps),
        "s2_fp_top10": top[:10],
        "note": ("원인은 **자동 판별 가능한 것만** 라벨을 붙였다. '미분류'는 추측으로 채우지 않은 것이다. "
                 "오탐 상위 10건은 정답표 밖 파일이지만, 정답표가 라인 마커 있는 챌린지만 담으므로 "
                 "**실제 취약점일 수 있다**(§PRECISION_CAVEAT)."),
    }
    p = OUT / f"repo_bench_{repo}_failures.json"
    p.write_text(json.dumps(res, ensure_ascii=False, indent=2))
    print(json.dumps({k: v for k, v in res.items()
                      if k not in ("missed", "s2_fp_top10")}, ensure_ascii=False, indent=2))
    print(f"저장: {p}")


if __name__ == "__main__":
    main(sys.argv[1])
