"""
서빙 경로 연속점수 검증 (OPPOINT §2-a)
=======================================
`scripts/api_rebuild.py` 의 `_score()` 가 내는 점수가
`rebuild/score_logprob.py` 가 낸 오프라인 점수와 같은 것을 재는지 확인한다.

이게 어긋나면 오늘의 운영점 분석 전체가 배포와 무관한 숫자가 된다.
비교 대상은 **배포되는 것과 같은 산출물** — GGUF(Q4_K_M) + adapter_v1_fix.gguf 를
llama-server 에 올린 상태다. 오프라인 점수는 bf16 4bit unsloth 경로이므로
**수치가 정확히 같을 수 없다.** 따라서 두 가지를 본다:
  1. **부호 일치율** = 판정(취약/안전)이 같은 비율   ← 이게 실질적 관심사
  2. **순위 상관(Spearman)** = 임계값 이동 시 같은 순서로 잡히는가

사전: llama-server 가 8080 에 떠 있어야 한다.
실행: python3 rebuild/verify_serving_score.py [n]
출력: out/serving_score_check.json
"""
from __future__ import annotations

import json
import sys
from pathlib import Path

import requests

ROOT = Path(__file__).resolve().parent
REPO = ROOT.parent
sys.path.insert(0, str(REPO))

from scanops.core.logprob_score import PREFIX, score_from_probs, verify_token_ids  # noqa: E402

N = int(sys.argv[1]) if len(sys.argv) > 1 else 20
URL = "http://localhost:8080"
CHATML_TMPL = "<|im_start|>user\n{p}<|im_end|>\n<|im_start|>assistant\n"   # api_rebuild.py 와 동일


def tokenize(text: str) -> list[int]:
    r = requests.post(f"{URL}/tokenize", json={"content": text}, timeout=60)
    r.raise_for_status()
    return r.json().get("tokens", [])


def logprobs(prompt: str) -> list[dict]:
    body = {"prompt": prompt, "n_predict": 1, "temperature": 0.0,
            "n_probs": 40, "post_sampling_probs": False}
    r = requests.post(f"{URL}/completion", json=body, timeout=300)
    r.raise_for_status()
    cps = r.json().get("completion_probabilities") or []
    if not cps:
        return []
    return cps[0].get("probs") or cps[0].get("top_logprobs") or []


def spearman(a: list[float], b: list[float]) -> float:
    def rank(xs):
        order = sorted(range(len(xs)), key=lambda i: xs[i])
        r = [0.0] * len(xs)
        for pos, i in enumerate(order):
            r[i] = pos
        return r
    ra, rb = rank(a), rank(b)
    n = len(a)
    ma, mb = sum(ra) / n, sum(rb) / n
    cov = sum((x - ma) * (y - mb) for x, y in zip(ra, rb))
    va = sum((x - ma) ** 2 for x in ra) ** 0.5
    vb = sum((y - mb) ** 2 for y in rb) ** 0.5
    return round(cov / (va * vb), 4) if va and vb else 0.0


def main() -> None:
    tok = verify_token_ids(tokenize)
    print(f"[token] {tok}")

    off = [json.loads(l) for l in (ROOT / "out" / "v1_logprob_test.jsonl").open()]
    data = [json.loads(l) for l in (ROOT / "data" / "test.jsonl").open()]
    assert len(off) == len(data), "오프라인 점수와 데이터 길이가 다르다"

    rows = []
    for i in range(min(N, len(data))):
        probs = logprobs(CHATML_TMPL.format(p=data[i]["prompt"]) + PREFIX)
        s = score_from_probs(probs)
        o = off[i]["score"]
        rows.append({
            "i": i, "gold": data[i]["meta"]["label"],
            "offline_score": round(o, 4), "serving_score": s,
            "offline_pred": "vuln" if o >= 0 else "safe",
            "serving_pred": (None if s is None else ("vuln" if s >= 0 else "safe")),
            "n_probs_returned": len(probs),
        })
        print(f"  [{i}] gold={rows[-1]['gold']:5s} off={o:+.4f} srv="
              f"{'None' if s is None else f'{s:+.4f}'} "
              f"({rows[-1]['offline_pred']} vs {rows[-1]['serving_pred']})")

    ok = [r for r in rows if r["serving_score"] is not None]
    agree = sum(1 for r in ok if r["offline_pred"] == r["serving_pred"])
    out = {
        "n_requested": N, "n_scored": len(ok), "n_none": len(rows) - len(ok),
        "token_id_check": tok,
        "serving": "llama-server + Qwen3.5-9B-Q4_K_M.gguf + adapter_v1_fix.gguf (배포 산출물)",
        "offline": "rebuild/score_logprob.py (unsloth 4bit) — out/v1_logprob_test.jsonl",
        "pred_agreement": round(agree / len(ok), 4) if ok else None,
        "spearman_score": spearman([r["offline_score"] for r in ok],
                                   [r["serving_score"] for r in ok]) if len(ok) > 2 else None,
        "note": "두 경로는 양자화가 달라 점수가 정확히 같을 수 없다. 부호(판정) 일치율과 "
                "순위 상관으로 '같은 것을 재는가'를 본다.",
        "rows": rows,
    }
    p = ROOT / "out" / "serving_score_check.json"
    p.write_text(json.dumps(out, ensure_ascii=False, indent=2))
    print(f"\n판정 일치율 {out['pred_agreement']}  순위상관 {out['spearman_score']}  "
          f"None {out['n_none']}건")
    print(f"→ {p}")


if __name__ == "__main__":
    main()
