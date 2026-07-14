"""
ScanOps 재구축 — 외부 벤치마크 채점: Claude (로컬 실행, GPU 불필요)
====================================================================
우리 모델과 완전 동일 조건 비교: 같은 {primevul,cleanvul}_test.jsonl,
같은 prompt, 같은 파서·채점(bench_common.py). 다른 건 답 생성 주체뿐.
모델은 내부 test 비교 때와 동일하게 claude-sonnet-5 (compare_apis.py와 일치).

이번엔 Message Batches API 사용 — 이유:
  - 건수가 큼(CleanVul ~1만 건+) → 배치는 토큰 단가 50% 할인
  - 실시간일 필요 없음 (대부분 1시간 내, 최대 24시간)
동작: 요청 일괄 제출 → batch id를 out/에 저장 → 폴링 → 결과 수집·채점.
중간에 끊겨도 저장된 batch id로 재실행하면 제출 없이 이어서 폴링한다.

환경변수: ANTHROPIC_API_KEY (scanops-model/.env)
실행:  .venv/bin/python rebuild/compare_claude_external.py primevul
       .venv/bin/python rebuild/compare_claude_external.py cleanvul
출력:  out/compare_claude_{name}_predictions.jsonl / _report.json
"""
from __future__ import annotations

import json
import os
import sys
import time
from pathlib import Path

from bench_common import build_report, load_jsonl, parse

ROOT = Path(__file__).resolve().parent
MODEL = "claude-sonnet-5"   # 내부 test 비교(compare_apis.py)와 동일 모델
MAX_TOKENS = 400
POLL_SEC = 60

# 내부 test 비교 때와 동일한 시스템 프롬프트 (compare_apis.py와 일치)
SYSTEM = ("You are a security code analyzer. Analyze the given code and respond "
          "ONLY in the exact 4-line format requested. Do not add explanation before or after.")

# 보정 프롬프트 (ablation 전용 — 본 비교표에는 쓰지 않음, 부록용)
# Claude의 과잉 경보를 줄이는 세 손잡이: ① 구체적 공격 경로가 보일 때만 취약 판정
# ② "검증이 안 보인다"는 취약의 근거가 아님 ③ 기저율 힌트(절반가량은 안전).
SYSTEM_CALIBRATED = (
    "You are a security code analyzer. Analyze the given code and respond ONLY in the "
    "exact 4-line format requested. Do not add explanation before or after.\n"
    "Judging rules: Report a vulnerability ONLY if a concrete, exploitable flaw is visible "
    "in the shown code itself. The absence of visible input validation is NOT sufficient "
    "evidence — the caller may validate. About half of the inputs you will see are safe "
    "(patched) code. If you cannot point to a specific flaw, answer NONE."
)

# .env 로드 (간단 파서 — compare_apis.py와 동일)
for line in (ROOT.parent / ".env").read_text().splitlines():
    if "=" in line and not line.strip().startswith("#"):
        k, _, v = line.partition("=")
        os.environ.setdefault(k.strip(), v.strip())


def main() -> None:
    import anthropic
    from anthropic.types.message_create_params import MessageCreateParamsNonStreaming
    from anthropic.types.messages.batch_create_params import Request

    name = sys.argv[1] if len(sys.argv) > 1 else "primevul"
    calibrated = len(sys.argv) > 2 and sys.argv[2] == "calibrated"   # ablation 모드
    system = SYSTEM_CALIBRATED if calibrated else SYSTEM
    tag = f"{name}_calibrated" if calibrated else name
    rows = load_jsonl(ROOT / "data" / f"{name}_test.jsonl")
    batch_id_file = ROOT / "out" / f"claude_batch_{tag}.id"
    client = anthropic.Anthropic()

    # ── ① 제출 (이미 제출한 batch id가 있으면 재사용 = 이중 과금 방지) ──────
    if batch_id_file.exists():
        batch_id = batch_id_file.read_text().strip()
        print(f"[{tag}] 기존 배치 이어서 폴링: {batch_id}")
    else:
        print(f"[{tag}] {len(rows)}건 배치 제출 (모델: {MODEL}, calibrated={calibrated})")
        requests = [
            Request(
                custom_id=f"i{i}",   # 결과는 순서 보장이 없어서 인덱스를 id에 박아둠
                params=MessageCreateParamsNonStreaming(
                    model=MODEL, max_tokens=MAX_TOKENS, system=system,
                    messages=[{"role": "user", "content": r["prompt"]}],
                ),
            )
            for i, r in enumerate(rows)
        ]
        batch = client.messages.batches.create(requests=requests)
        batch_id = batch.id
        batch_id_file.parent.mkdir(exist_ok=True)
        batch_id_file.write_text(batch_id)
        print(f"batch id 저장: {batch_id_file} ({batch_id})")

    # ── ② 폴링: ended까지 대기 ───────────────────────────────────────────────
    while True:
        b = client.messages.batches.retrieve(batch_id)
        if b.processing_status == "ended":
            break
        c = b.request_counts
        print(f"  처리 중… 완료 {c.succeeded} / 오류 {c.errored} / 진행 {c.processing}", flush=True)
        time.sleep(POLL_SEC)
    print(f"배치 완료: 성공 {b.request_counts.succeeded} / 오류 {b.request_counts.errored}")

    # ── ③ 결과 수집 → custom_id로 원래 행과 재결합 ──────────────────────────
    raw_by_idx: dict[int, str] = {}
    for result in client.messages.batches.results(batch_id):
        idx = int(result.custom_id[1:])
        if result.result.type == "succeeded":
            msg = result.result.message
            raw_by_idx[idx] = "".join(b.text for b in msg.content if b.type == "text")
        else:
            raw_by_idx[idx] = f"ERROR: {result.result.type}"

    preds = []
    for i, r in enumerate(rows):
        raw = raw_by_idx.get(i, "ERROR: missing")
        preds.append({"meta": r["meta"], "raw": raw.strip()[:500], **parse(raw)})

    out_pred = ROOT / "out" / f"compare_claude_{tag}_predictions.jsonl"
    with out_pred.open("w") as f:
        for p in preds:
            f.write(json.dumps(p, ensure_ascii=False) + "\n")

    report = build_report(preds, engine=MODEL + (" (calibrated prompt)" if calibrated else ""), dataset=name)
    out_report = ROOT / "out" / f"compare_claude_{tag}_report.json"
    out_report.write_text(json.dumps(report, ensure_ascii=False, indent=2))
    print(json.dumps({k: report[k] for k in ("overall", "pairwise") if k in report}, indent=2))
    print(f"저장: {out_pred}, {out_report}")


if __name__ == "__main__":
    main()
