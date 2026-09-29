"""Phase 2 — Critic 전략 실행기 (전략 D/A/B/C + 탐색 루프 공용).

모든 전략은 **어제와 같은 98건**(tune, v3 vuln ∧ path 보유)을 대상으로 하고
같은 지표(T1/마진/YES/UNPARSED/T3)를 낸다 — 전략 간 비교가 성립해야 하기 때문이다.

  python joern/critic_strategies.py <strategy> [--limit N]

전략:
  A_external   외부 API (상한 측정 전용, 프로덕션 불가)
  D_base       로컬 베이스 Qwen3.5-9B (어댑터 없음) — 어제 프롬프트 그대로
  B_detect     Slice-Detect: 슬라이스를 4줄 판정 서식으로 물음 (b1=슬라이스만, b2=+시그니처)
  C_raw        raw completion (ChatML 템플릿 없이)
"""
from __future__ import annotations

import argparse
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

from scanops.core.llm_critic import build_prompt, parse_verdict, strip_think  # noqa: E402

OUT = ROOT / "rebuild" / "out"
SEED = 42

# 로컬 베이스 모델 서버 (전략 D)
BASE_URL = os.getenv("BASE_LLM_URL", "http://127.0.0.1:8099")


def load_targets(source: str = "v3") -> list[dict]:
    """어제 Critic 대상과 동일한 98건 (v3 vuln ∧ path 보유).

    source="union" 이면 같은 case_id 에 대해 **모든 흐름의 합집합** 슬라이스를 쓴다(전략 E).
    """
    rows = [json.loads(l) for l in (OUT / "joern_v3_raw_cleanvul_v2_tune.jsonl").open()]
    base = [r for r in rows if r["joern_verdict"] == "vuln" and r.get("path")]
    if source != "union":
        return base
    want = {r["case_id"] for r in base}
    uni = {}
    for l in (OUT / "slices_union_v4.jsonl").open():
        o = json.loads(l)
        if o["case_id"] in want and o.get("path"):
            uni[o["case_id"]] = o
    # 어제와 같은 순서·집합을 유지하되 path 만 union 으로 교체
    out = []
    for r in base:
        u = uni.get(r["case_id"])
        if u is None:
            continue
        out.append({**r, "path": u["path"],
                    "categories": u.get("categories") or r.get("categories"),
                    "n_flows": u.get("n_flows")})
    return out


def paired_sample(targets: list[dict], n_pairs: int) -> list[dict]:
    """양쪽(vuln/safe)이 다 있는 쌍에서 n_pairs 쌍(=2n건)을 seed 고정으로."""
    by_pair: dict[str, dict[str, dict]] = {}
    for r in targets:
        by_pair.setdefault(r["pair_id"], {})[r["label"]] = r
    full = sorted([p for p, d in by_pair.items() if "vuln" in d and "safe" in d])
    rng = random.Random(SEED)
    picked = full if len(full) <= n_pairs else rng.sample(full, n_pairs)
    out = []
    for p in sorted(picked):
        out.append(by_pair[p]["vuln"])
        out.append(by_pair[p]["safe"])
    return out


# ── 전략 A: 외부 API ────────────────────────────────────────────────────────

def run_external(r: dict) -> dict:
    """어제와 **동일한 프롬프트**를 외부 모델에 던진다(비교 성립을 위해)."""
    import urllib.request
    key = os.environ.get("ANTHROPIC_API_KEY", "")
    if not key:
        return {"verdict": "UNPARSED", "reason": "", "error": "no_api_key", "usage": {}}
    prompt = build_prompt((r.get("categories") or ["unknown"])[0], r["lang"], r["path"])
    body = json.dumps({
        "model": os.getenv("EXTERNAL_MODEL", "claude-haiku-4-5-20251001"),
        "max_tokens": 300,
        "temperature": 0,
        "messages": [{"role": "user", "content": prompt}],
    }).encode()
    req = urllib.request.Request(
        "https://api.anthropic.com/v1/messages", data=body,
        headers={"content-type": "application/json", "x-api-key": key,
                 "anthropic-version": "2023-06-01"})
    try:
        with urllib.request.urlopen(req, timeout=120) as resp:
            d = json.loads(resp.read())
    except Exception as e:  # noqa: BLE001
        return {"verdict": "UNPARSED", "reason": "", "error": str(e)[:200], "usage": {}}
    txt = "".join(b.get("text", "") for b in d.get("content", []))
    v = parse_verdict(txt)
    m = re.search(r"SANITIZED\s*[:\-–—]?\s*(YES|NO)", strip_think(txt), re.I)
    reason = strip_think(txt)[m.end():].strip()[:300] if m else strip_think(txt)[:300]
    return {"verdict": v, "reason": reason, "error": None, "usage": d.get("usage", {})}


# ── 전략 D: 로컬 베이스 모델 ────────────────────────────────────────────────

def run_base(r: dict, variant: str = "v1") -> dict:
    """로컬 llama-server(베이스 Qwen3.5-9B, 어댑터 없음). 어제 프롬프트 그대로."""
    import urllib.request
    prompt = build_prompt((r.get("categories") or ["unknown"])[0], r["lang"], r["path"],
                          variant=variant)
    # Qwen3.5 는 <think> 를 먼저 낸다. max_tokens 400 이면 사고만 하다 잘려
    # **본문이 빈 문자열**로 온다(finish_reason=length, 실측 20/20 UNPARSED).
    # 사고를 끄면 4s/건으로 빨라지고 형식도 지킨다.
    body = json.dumps({
        "messages": [{"role": "user", "content": prompt}],
        "temperature": 0.0, "max_tokens": 400,
        "chat_template_kwargs": {"enable_thinking": False},
    }).encode()
    req = urllib.request.Request(f"{BASE_URL}/v1/chat/completions", data=body,
                                 headers={"content-type": "application/json"})
    try:
        with urllib.request.urlopen(req, timeout=300) as resp:
            d = json.loads(resp.read())
    except Exception as e:  # noqa: BLE001
        return {"verdict": "UNPARSED", "reason": "", "error": str(e)[:200], "usage": {}}
    txt = (d.get("choices") or [{}])[0].get("message", {}).get("content", "")
    v = parse_verdict(txt)
    cleaned = strip_think(txt)
    m = re.search(r"SANITIZED\s*[:\-–—]?\s*(YES|NO)", cleaned, re.I)
    reason = cleaned[m.end():].strip()[:300] if m else cleaned[:300]
    return {"verdict": v, "reason": reason, "error": None, "usage": d.get("usage", {})}


# ── 지표 ────────────────────────────────────────────────────────────────────

def metrics(recs: list[dict], all_targets: list[dict]) -> dict:
    scored = [x for x in recs if x["critic"] in ("YES", "NO")]
    unp = [x for x in recs if x["critic"] == "UNPARSED"]
    correct = sum(1 for x in scored
                  if (x["critic"] == "YES" and x["label"] == "safe")
                  or (x["critic"] == "NO" and x["label"] == "vuln"))
    t1 = correct / len(scored) if scored else 0.0
    base = sum(1 for x in scored if x["label"] == "vuln") / len(scored) if scored else 0.0

    by_pair: dict[str, dict[str, str]] = {}
    for x in recs:
        if x["critic"] in ("YES", "NO"):
            by_pair.setdefault(x["pair_id"], {})[x["label"]] = x["critic"]
    pairs = {p: d for p, d in by_pair.items() if "vuln" in d and "safe" in d}
    inner = (sum(1 for d in pairs.values() if d["vuln"] != d["safe"]) / len(pairs)
             if pairs else 0.0)
    yes_rate = (sum(1 for x in scored if x["critic"] == "YES") / len(scored)
                if scored else 0.0)
    t3 = "UNMEASURED" if len(pairs) < 10 else ("PASS" if inner > yes_rate else "FAIL")
    # 쌍 정답률: vuln→NO 이고 safe→YES 인 쌍
    pair_correct = (sum(1 for d in pairs.values()
                        if d["vuln"] == "NO" and d["safe"] == "YES") / len(pairs)
                    if pairs else 0.0)

    yes = sum(1 for x in scored if x["critic"] == "YES")
    m = {
        "n_target": len(recs), "n_scored": len(scored),
        "unparsed": len(unp),
        "unparsed_rate": round(len(unp) / len(recs), 4) if recs else 0.0,
        "critic_yes": yes, "critic_no": len(scored) - yes,
        "T1_accuracy": round(t1, 4), "T1_trivial_always_NO": round(base, 4),
        "T1_margin": round(t1 - base, 4),
        "T3_status": t3, "T3_pairs": len(pairs),
        "T3_inner_disagreement": round(inner, 4), "T3_yes_rate": round(yes_rate, 4),
        "pair_correct": round(pair_correct, 4),
        "by_lang": {},
    }
    for lang in sorted({x["lang"] for x in scored}):
        s = [x for x in scored if x["lang"] == lang]
        c = sum(1 for x in s if (x["critic"] == "YES" and x["label"] == "safe")
                or (x["critic"] == "NO" and x["label"] == "vuln"))
        m["by_lang"][lang] = {"n": len(s), "acc": round(c / len(s), 4) if s else 0.0,
                              "yes": sum(1 for x in s if x["critic"] == "YES")}
    # 사전등록 게이트
    m["PROMISING"] = bool(m["T1_margin"] >= 0.15 and yes >= 5
                          and m["unparsed_rate"] < 0.20)
    return m


RUNNERS = {"A_external": run_external, "D_base": run_base,
           "E_union_external": run_external, "E_union_base": run_base}


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("strategy")
    ap.add_argument("--limit", type=int, default=0, help="0=전건 98, N=쌍 N/2개")
    ap.add_argument("--variant", default="v1")
    args = ap.parse_args()

    targets = load_targets("union" if args.strategy.startswith("E_") else "v3")
    if args.limit:
        targets = paired_sample(targets, args.limit // 2)
    print(f"[{args.strategy}] 대상 {len(targets)}건", flush=True)

    raw_path = OUT / f"critic_v4_{args.strategy}.jsonl"
    done = {}
    if raw_path.exists():
        for line in raw_path.open():
            try:
                o = json.loads(line)
                done[o["case_id"]] = o
            except Exception:  # noqa: BLE001
                pass

    fn = RUNNERS[args.strategy]
    t0 = time.time()
    usage_tot = {"input_tokens": 0, "output_tokens": 0}
    with raw_path.open("a") as fh:
        todo = [r for r in targets if r["case_id"] not in done]
        for i, r in enumerate(todo, 1):
            res = fn(r, args.variant) if args.strategy.endswith("_base") else fn(r)
            for k in usage_tot:
                usage_tot[k] += (res.get("usage") or {}).get(k, 0)
            rec = {"case_id": r["case_id"], "pair_id": r["pair_id"], "lang": r["lang"],
                   "label": r["label"], "category": (r.get("categories") or ["unknown"])[0],
                   "critic": res["verdict"], "reason": res["reason"],
                   "error": res["error"], "strategy": args.strategy}
            fh.write(json.dumps(rec, ensure_ascii=False) + "\n")
            fh.flush()
            done[r["case_id"]] = rec
            if i % 10 == 0 or i == len(todo):
                print(f"[{args.strategy}] {i}/{len(todo)} "
                      f"{(time.time()-t0)/max(1,i):.1f}s/건", flush=True)

    recs = [done[r["case_id"]] for r in targets if r["case_id"] in done]
    m = metrics(recs, targets)
    m["strategy"] = args.strategy
    m["usage"] = usage_tot
    (OUT / f"critic_v4_{args.strategy}_metrics.json").write_text(
        json.dumps(m, indent=2, ensure_ascii=False))
    print(json.dumps(m, indent=2, ensure_ascii=False))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
