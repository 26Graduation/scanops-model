"""Phase A — 단건 헤드투헤드 러너 (Claude Message Batches, 재개·예산 기록)

이미 만들어진 프롬프트 jsonl(`rebuild/data/*.jsonl`, 각 행에 `prompt`·`meta`)을
그대로 Claude 에 보낸다. **프롬프트를 새로 만들지 않는다** = PARITY 의 정의(사양 §2-b).

우리(v1) 점수는 이미 있는 파일을 쓴다(사양 §1). 여기서는 외부만 채운다.

실행:
    python rebuild/headtohead.py submit  <dataset> [strong]
    python rebuild/headtohead.py collect <dataset> [strong]
    python rebuild/headtohead.py budget

예산: 사양 §4 — Anthropic 합계 ≤ $15. `out/h2h_budget.json` 에 누적한다.
90% 를 넘으면 **새 제출을 거부**한다(진행 중인 배치는 수거한다).
"""
from __future__ import annotations

import json
import os
import sys
import time
from pathlib import Path

ROOT = Path(__file__).resolve().parent
OUT = ROOT / "out"
DATA = ROOT / "data"
sys.path.insert(0, str(ROOT))
from bench_common import build_report, load_jsonl, parse  # noqa: E402

MODEL = "claude-opus-5"
BUDGET_USD = 15.0
IN_PER_MTOK, OUT_PER_MTOK, BATCH_DISCOUNT = 5.0, 25.0, 0.5

SYSTEM_PARITY = ("You are a security code analyzer. Analyze the given code and respond "
                 "ONLY in the exact 4-line format requested. Do not add explanation before or after.")
SYSTEM_STRONG = (
    "You are a senior application security engineer performing a code review. "
    "Think step by step about data flow: identify untrusted sources, follow them to "
    "dangerous sinks, and check whether any validation, encoding, or sanitization "
    "breaks the flow. Consider that the file may be safe. "
    "AFTER your analysis, end your reply with ONLY the exact 4-line format requested, "
    "with nothing after it."
)

DATASETS = {                       # 사양 §4 우선순위 순
    "test": "test.jsonl",                       # ② 내부 test 1,197
    "dw_P0": "dw_P0.jsonl",                     # ③ PR 쌍 현행 형식 400
    "dw_P2": "dw_P2.jsonl",                     # ③ PR 쌍 [DIFF] 형식 400
    "cybernative154": "cybernative154.jsonl",   # ④
    "cvefixes157": "cvefixes157.jsonl",         # ④
}

BUDGET_FILE = OUT / "h2h_budget.json"


def _load_env() -> None:
    for line in (ROOT.parent / ".env").read_text().splitlines():
        if "=" in line and not line.strip().startswith("#"):
            k, _, v = line.partition("=")
            os.environ.setdefault(k.strip(), v.strip())


def budget() -> dict:
    if BUDGET_FILE.exists():
        return json.loads(BUDGET_FILE.read_text())
    return {"spent_usd": 0.0, "items": []}


def add_spend(label: str, usd: float, detail: dict) -> None:
    b = budget()
    b["spent_usd"] = round(b["spent_usd"] + usd, 4)
    b["items"].append({"label": label, "usd": round(usd, 4),
                       "at": time.strftime("%Y-%m-%d %H:%M:%S %Z"), **detail})
    BUDGET_FILE.write_text(json.dumps(b, ensure_ascii=False, indent=2))


def tag_of(name: str, strong: bool) -> str:
    return f"{name}_strong" if strong else f"{name}_parity"


def submit(name: str, strong: bool = False) -> None:
    import anthropic
    from anthropic.types.message_create_params import MessageCreateParamsNonStreaming
    from anthropic.types.messages.batch_create_params import Request
    _load_env()
    b = budget()
    if b["spent_usd"] >= BUDGET_USD * 0.9:
        print(f"[예산] {b['spent_usd']:.2f} / {BUDGET_USD} — 90% 초과, 제출 거부")
        return
    rows = load_jsonl(DATA / DATASETS[name])
    tag = tag_of(name, strong)
    id_file = OUT / f"h2h_batch_{tag}.id"
    if id_file.exists():
        print(f"[{tag}] 이미 제출됨: {id_file.read_text().strip()}")
        return
    client = anthropic.Anthropic()
    params = dict(model=MODEL, max_tokens=4000 if strong else 400,
                  system=SYSTEM_STRONG if strong else SYSTEM_PARITY)
    if not strong:
        params["thinking"] = {"type": "disabled"}
    reqs = [Request(custom_id=f"i{i}",
                    params=MessageCreateParamsNonStreaming(
                        **params, messages=[{"role": "user", "content": r["prompt"]}]))
            for i, r in enumerate(rows)]
    batch = client.messages.batches.create(requests=reqs)
    id_file.write_text(batch.id)
    print(f"[{tag}] {len(rows)}건 제출 → {batch.id}")


def collect(name: str, strong: bool = False) -> None:
    import anthropic
    _load_env()
    rows = load_jsonl(DATA / DATASETS[name])
    tag = tag_of(name, strong)
    id_file = OUT / f"h2h_batch_{tag}.id"
    if not id_file.exists():
        print(f"[{tag}] 제출 기록 없음")
        return
    bid = id_file.read_text().strip()
    client = anthropic.Anthropic()
    b = client.messages.batches.retrieve(bid)
    if b.processing_status != "ended":
        c = b.request_counts
        print(f"[{tag}] 아직 처리 중 — 성공 {c.succeeded} / 오류 {c.errored} / 진행 {c.processing}")
        return
    raw_by, usage = {}, {"input": 0, "output": 0}
    for r in client.messages.batches.results(bid):
        i = int(r.custom_id[1:])
        if r.result.type == "succeeded":
            m = r.result.message
            raw_by[i] = "".join(x.text for x in m.content if x.type == "text")
            usage["input"] += m.usage.input_tokens
            usage["output"] += m.usage.output_tokens
        else:
            raw_by[i] = f"ERROR: {r.result.type}"
    preds = [{"meta": r["meta"], "raw": raw_by.get(i, "ERROR: missing").strip()[:500],
              **parse(raw_by.get(i, ""))} for i, r in enumerate(rows)]
    p = OUT / f"h2h_claude_{tag}_predictions.jsonl"
    with p.open("w") as f:
        for x in preds:
            f.write(json.dumps(x, ensure_ascii=False) + "\n")
    rep = build_report(preds, engine=MODEL + (" STRONG" if strong else " PARITY"), dataset=name)
    cost = (usage["input"] / 1e6 * IN_PER_MTOK
            + usage["output"] / 1e6 * OUT_PER_MTOK) * BATCH_DISCOUNT
    rep["_meta"] = {"model": MODEL, "batch_id": bid, "strong": strong,
                    "usage": usage, "cost_usd": round(cost, 4),
                    "collected_at": time.strftime("%Y-%m-%d %H:%M:%S %Z"),
                    "unparsed": sum(1 for x in preds if x["label"] == "parse_fail"),
                    "unparsed_rate": round(sum(1 for x in preds
                                               if x["label"] == "parse_fail") / len(preds), 4)}
    (OUT / f"h2h_claude_{tag}_report.json").write_text(json.dumps(rep, ensure_ascii=False, indent=2))
    add_spend(tag, cost, {"batch_id": bid, "n": len(rows), "usage": usage})
    print(json.dumps({k: rep[k] for k in ("overall", "pairwise", "_meta") if k in rep},
                     ensure_ascii=False, indent=2))


if __name__ == "__main__":
    OUT.mkdir(exist_ok=True)
    cmd = sys.argv[1]
    if cmd == "budget":
        print(json.dumps(budget(), ensure_ascii=False, indent=2))
    elif cmd == "submit":
        submit(sys.argv[2], strong=("strong" in sys.argv[3:]))
    elif cmd == "collect":
        collect(sys.argv[2], strong=("strong" in sys.argv[3:]))
    else:
        raise SystemExit(f"unknown cmd {cmd}")
