"""Phase A 배치 id 를 커밋 가능한 파일로 남긴다 (.id 파일은 .gitignore 대상)."""
from __future__ import annotations

import glob
import json
import os

ids = {}
for f in sorted(glob.glob("rebuild/out/h2h_batch_*.id")):
    name = os.path.basename(f)[len("h2h_batch_"):-len(".id")]
    ids[name] = open(f).read().strip()

out = {
    "note": ("Phase A 배치 — 제출됐고 약 5시간 동안 succeeded 0 이라 이번 세션에서 수거하지 못했다. "
             "**비용은 발생한다.** 다음 세션에서 `python rebuild/headtohead.py collect <dataset>` 로 "
             "이어서 수거한다(같은 batch id 를 재사용하므로 이중 과금 없음)."),
    "submitted_at_kst": "2026-08-17 22:0x",
    "model": "claude-opus-5",
    "arm": "PARITY (thinking disabled, max_tokens 400, PROMPT_TMPL 바이트 동일)",
    "datasets": {"test": 1197, "dw_P0": 400, "dw_P2": 400,
                 "cybernative154": 154, "cvefixes157": 157},
    "n_units_total": 2308,
    "estimated_cost_usd_batch50pct": 11.2,
    "batch_ids": ids,
}
with open("rebuild/out/h2h_pending_batches.json", "w") as f:
    json.dump(out, f, ensure_ascii=False, indent=2)
print(json.dumps(out, ensure_ascii=False, indent=2))
