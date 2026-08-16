"""Phase 2 — Critic tune 게이트 (T1/T2/T3). 사전등록: REPORT_V3 §3-0.

  python joern/critic_gate.py            # tune 전건
  python joern/critic_gate.py --limit 60 # 층화 축소 (비용 폴백)

출력:
  rebuild/out/critic_raw_cleanvul_v2_tune.jsonl   케이스별 Critic 응답 (append·재개)
  rebuild/out/critic_gate_tune.json               T1/T2/T3 + 판정
"""
from __future__ import annotations

import argparse
import difflib
import json
import os
import random
import re
import sys
import time
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))

for _line in (ROOT / ".env").read_text().splitlines():
    if "=" in _line and not _line.strip().startswith("#"):
        _k, _v = _line.strip().split("=", 1)
        os.environ.setdefault(_k, _v.strip().strip('"').strip("'"))

from joern.bench_joern import extract_code  # noqa: E402
from scanops.core.llm_critic import critique  # noqa: E402

OUT = ROOT / "rebuild" / "out"
DATA = ROOT / "rebuild" / "data"
SEED = 42

_IDENT_RE = re.compile(r"[A-Za-z_][A-Za-z0-9_]{2,}")
# 언어 키워드는 '패치 관련 식별자'로 세지 않는다 — 어디에나 있어 포함률이 부풀려진다.
_STOP = {
    "public", "private", "protected", "static", "final", "void", "return", "class", "import",
    "package", "new", "this", "null", "true", "false", "int", "long", "double", "float",
    "boolean", "char", "String", "def", "self", "None", "True", "False", "elif", "else",
    "for", "while", "try", "except", "catch", "throw", "throws", "finally", "const", "let",
    "var", "function", "async", "await", "require", "module", "exports", "from", "and",
    "not", "with", "assert", "print", "len", "str", "list", "dict", "set", "get", "if",
}


def load_pair_code(split: str) -> dict[str, str]:
    """case_id → 원본 코드."""
    out: dict[str, str] = {}
    for line in (DATA / f"cleanvul_v2_{split}.jsonl").open():
        r = json.loads(line)
        m = r["meta"]
        out[f"{m['pair_id']}|{m['label']}"] = extract_code(r["prompt"])
    return out


def patch_identifiers(vuln_code: str, safe_code: str) -> set[str]:
    """쌍의 diff 에서 바뀐 줄의 식별자."""
    idents: set[str] = set()
    diff = difflib.unified_diff(vuln_code.splitlines(), safe_code.splitlines(), n=0)
    for ln in diff:
        if ln.startswith(("+++", "---", "@@")):
            continue
        if ln.startswith(("+", "-")):
            idents |= {t for t in _IDENT_RE.findall(ln) if t not in _STOP}
    return idents


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--limit", type=int, default=0, help="0=전건, N=층화 N건")
    ap.add_argument("--variant", default="v1", help="프롬프트 변형 (v1=사전등록 원문, v2=1회 개정)")
    args = ap.parse_args()

    suffix = "" if args.variant == "v1" else f"_{args.variant}"
    rows = [json.loads(l) for l in (OUT / "joern_v3_raw_cleanvul_v2_tune.jsonl").open()]
    targets = [r for r in rows if r["joern_verdict"] == "vuln" and r.get("path")]
    print(f"[gate] tune n={len(rows)} joern_v3_vuln(with path)={len(targets)}", flush=True)
    if not targets:
        (OUT / f"critic_gate_tune{suffix}.json").write_text(json.dumps(
            {"verdict": "CRITIC-KILL", "reason": "대상 0건", "n_target": 0}, indent=2))
        print("[gate] CRITIC-KILL (대상 0건)")
        return 0

    if args.limit and len(targets) > args.limit:
        rng = random.Random(SEED)
        bylang: dict[str, list] = {}
        for r in targets:
            bylang.setdefault(r["lang"], []).append(r)
        per = max(1, args.limit // max(1, len(bylang)))
        picked = []
        for lang in sorted(bylang):
            pool = sorted(bylang[lang], key=lambda r: r["case_id"])
            picked.extend(pool if len(pool) <= per else rng.sample(pool, per))
        targets = picked
        print(f"[gate] 층화 축소 → {len(targets)}건", flush=True)

    # T3 대상: 같은 pair 의 vuln/safe 양쪽이 모두 v3 vuln 이고 path 보유
    by_pair: dict[str, dict[str, dict]] = {}
    for r in rows:
        if r["joern_verdict"] == "vuln" and r.get("path"):
            by_pair.setdefault(r["pair_id"], {})[r["label"]] = r
    t3_pairs = {p: d for p, d in by_pair.items() if "vuln" in d and "safe" in d}
    print(f"[gate] T3 양쪽-path 쌍 = {len(t3_pairs)}", flush=True)

    # T3 쌍의 양쪽도 Critic 대상에 포함시킨다
    need = {r["case_id"]: r for r in targets}
    for d in t3_pairs.values():
        for r in d.values():
            need.setdefault(r["case_id"], r)

    raw_path = OUT / f"critic_raw_cleanvul_v2_tune{suffix}.jsonl"
    done: dict[str, dict] = {}
    if raw_path.exists():
        for line in raw_path.open():
            try:
                o = json.loads(line)
                done[o["case_id"]] = o
            except Exception:  # noqa: BLE001
                pass
    todo = [r for cid, r in need.items() if cid not in done]
    print(f"[gate] critic 호출 대상 {len(need)} (완료 {len(done)}, 남음 {len(todo)})", flush=True)

    t0 = time.time()
    with raw_path.open("a") as fh:
        for i, r in enumerate(todo, 1):
            cat = (r.get("categories") or ["unknown"])[0]
            res = critique(cat, r["lang"], r["path"], variant=args.variant)
            rec = {"case_id": r["case_id"], "pair_id": r["pair_id"], "lang": r["lang"],
                   "label": r["label"], "category": cat,
                   "critic": res["verdict"], "reason": res["reason"],
                   "error": res["error"], "path_len": len(r["path"])}
            fh.write(json.dumps(rec, ensure_ascii=False) + "\n")
            fh.flush()
            done[r["case_id"]] = rec
            if i % 10 == 0 or i == len(todo):
                el = time.time() - t0
                print(f"[gate] {i}/{len(todo)}  {el/max(1,i):.1f}s/건  경과 {el/60:.1f}분", flush=True)

    # ── T1 ────────────────────────────────────────────────────────────────
    ev = [done[r["case_id"]] for r in targets if r["case_id"] in done]
    unparsed = [x for x in ev if x["critic"] == "UNPARSED"]
    scored = [x for x in ev if x["critic"] in ("YES", "NO")]
    correct = sum(1 for x in scored
                  if (x["critic"] == "YES" and x["label"] == "safe")
                  or (x["critic"] == "NO" and x["label"] == "vuln"))
    t1 = correct / len(scored) if scored else 0.0
    # 자명 기준선 "항상 NO" = gold_vuln 비율
    base = sum(1 for x in scored if x["label"] == "vuln") / len(scored) if scored else 0.0

    # ── T2 ────────────────────────────────────────────────────────────────
    code = load_pair_code("tune")
    tgt_by_id = {r["case_id"]: r for r in targets}
    t2_n = t2_hit = 0
    for cid, r in tgt_by_id.items():
        pid = r["pair_id"]
        vc, sc = code.get(f"{pid}|vuln"), code.get(f"{pid}|safe")
        if not vc or not sc:
            continue
        idents = patch_identifiers(vc, sc)
        if not idents:
            continue
        t2_n += 1
        blob = " ".join((s.get("code") or "") for s in r["path"])
        if any(t in blob for t in idents):
            t2_hit += 1
    t2 = t2_hit / t2_n if t2_n else 0.0

    # ── T3 ────────────────────────────────────────────────────────────────
    t3_status, t3_detail = "UNMEASURED", {"pairs": len(t3_pairs)}
    if len(t3_pairs) >= 10:
        diffs, moves = [], []
        for pid, d in t3_pairs.items():
            a, b = done.get(d["vuln"]["case_id"]), done.get(d["safe"]["case_id"])
            if not a or not b:
                continue
            if a["critic"] not in ("YES", "NO") or b["critic"] not in ("YES", "NO"):
                continue
            diffs.append(1.0 if a["critic"] != b["critic"] else 0.0)
            moves.append(1.0 if a["critic"] == "YES" else 0.0)
            moves.append(1.0 if b["critic"] == "YES" else 0.0)
        if len(diffs) >= 10:
            inner = sum(diffs) / len(diffs)
            overall = sum(moves) / len(moves) if moves else 0.0
            t3_status = "PASS" if inner > overall else "FAIL"
            t3_detail = {"pairs_scored": len(diffs), "inner_pair_disagreement": round(inner, 4),
                         "overall_yes_rate": round(overall, 4)}
        else:
            t3_detail = {"pairs": len(t3_pairs), "pairs_scored": len(diffs)}

    # ── 판정 ──────────────────────────────────────────────────────────────
    passes_t1 = t1 >= base + 0.15
    if not passes_t1:
        verdict = "CRITIC-KILL"
    elif t2 >= 0.60 and t3_status == "PASS":
        verdict = "CRITIC-GO"
    else:
        verdict = "CRITIC-WEAK"

    result = {
        "prompt_variant": args.variant,
        "verdict": verdict,
        "n_target": len(targets), "n_scored": len(scored),
        "unparsed": len(unparsed),
        "unparsed_rate": round(len(unparsed) / len(ev), 4) if ev else 0.0,
        "T1_accuracy": round(t1, 4), "T1_trivial_always_NO": round(base, 4),
        "T1_margin": round(t1 - base, 4), "T1_required_margin": 0.15, "T1_pass": passes_t1,
        "T2_ident_inclusion": round(t2, 4), "T2_n": t2_n, "T2_pass": t2 >= 0.60,
        "T3_status": t3_status, "T3_detail": t3_detail,
        "critic_yes": sum(1 for x in scored if x["critic"] == "YES"),
        "critic_no": sum(1 for x in scored if x["critic"] == "NO"),
    }
    by_lang: dict[str, dict] = {}
    for lang in sorted({x["lang"] for x in scored}):
        s = [x for x in scored if x["lang"] == lang]
        c = sum(1 for x in s if (x["critic"] == "YES" and x["label"] == "safe")
                or (x["critic"] == "NO" and x["label"] == "vuln"))
        by_lang[lang] = {"n": len(s), "acc": round(c / len(s), 4) if s else 0.0,
                         "yes": sum(1 for x in s if x["critic"] == "YES")}
    result["by_lang"] = by_lang

    (OUT / f"critic_gate_tune{suffix}.json").write_text(json.dumps(result, indent=2, ensure_ascii=False))
    print(json.dumps(result, indent=2, ensure_ascii=False))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
