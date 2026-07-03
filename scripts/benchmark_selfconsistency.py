"""자기일관성(self-consistency) 벤치마크 — 단일 모델 k회 샘플링 다수결
================================================================
앙상블 외 성능개선 기법 검증: 같은 모델을 temperature>0 + seed 변화로 k회 호출해
다수결(≥ceil(k/2))로 판정. 모델 1개로 앙상블 유사 효과(경계 케이스 안정화)를 노린다.
비용 = 호출 k배 (단 RAM은 모델 1개).

실행: python scripts/benchmark_selfconsistency.py --model qwen2.5-coder-security-v16-1-7b:latest --k 3
산출: reports/results_sc_<bench>.json (llm=다수결, any=1표라도, graph 포함)
"""
from __future__ import annotations

import argparse
import json
import sys
import time
from pathlib import Path

import requests

BASE = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(BASE))
sys.path.insert(0, str(BASE / "scripts"))

from scripts.benchmark_qwen_rag import (OLLAMA_CHAT, SYSTEM_FT, build_ft_user_prompt,
                                        parse_response)
from scanops.core.multi_graph import analyze as analyze_code
from scripts.benchmark_v12 import metrics, _is_safe

BENCHES = ["cvefixes_benchmark", "owasp_method_bench",
           "cybernative_benchmark", "diversevul_benchmark"]


def _call(prompt: str, model: str, temp: float, seed: int) -> str:
    payload = {
        "model": model,
        "messages": [{"role": "system", "content": SYSTEM_FT},
                     {"role": "user", "content": prompt}],
        "stream": False,
        "options": {"temperature": temp, "top_p": 0.9, "seed": seed,
                    "num_predict": 200, "repeat_penalty": 1.3,
                    "stop": ["<|im_end|>", "<|endoftext|>", "[EMPTY_151643]"]},
    }
    r = requests.post(OLLAMA_CHAT, json=payload, timeout=90)
    r.raise_for_status()
    return r.json().get("message", {}).get("content", "")


def _flag(raw: str) -> bool:
    return not _is_safe(parse_response(raw).get("VULNERABILITY", "—"))


def run(model: str, k: int, temp: float, benches: list[str] | None = None):
    for bench in (benches or BENCHES):
        cases = [json.loads(l) for l in open(BASE / "data" / f"{bench}.jsonl") if l.strip()]
        rows = []
        t0 = time.time()
        print(f"\n벤치: {bench} | {len(cases)}케이스 | {model} | k={k} temp={temp}", flush=True)
        for i, c in enumerate(cases, 1):
            prompt = build_ft_user_prompt(c["language"], c["code"])
            votes = []
            for s in range(k):
                try:
                    votes.append(_flag(_call(prompt, model, temp, seed=41 + s)))
                except Exception:  # noqa: BLE001
                    votes.append(False)
            g = analyze_code(c["code"], c["language"])
            rows.append({"label": c["label"], "votes": votes,
                         "llm": sum(votes) >= (k // 2 + 1),   # 다수결
                         "any": any(votes),                   # 1표라도(고재현 변형)
                         "graph": g["verdict"]})
            if i % 20 == 0:
                el = time.time() - t0
                print(f"  {i}/{len(cases)} ({el/60:.1f}분)", flush=True)
        for key in ("llm", "any"):
            m = metrics(rows, key)
            print(f"  {key:4}: F1={m['f1']} 재현율={m['recall']}% 오탐률={m['fpr']}% 정확도={m['accuracy']}%")
        out = BASE / "reports" / f"results_sc_{bench}.json"
        out.write_text(json.dumps({"model": model, "k": k, "temp": temp,
                                   "llm": metrics(rows, "llm"), "any": metrics(rows, "any"),
                                   "cases": rows}, indent=2, ensure_ascii=False), encoding="utf-8")
        print(f"  저장: {out}", flush=True)


if __name__ == "__main__":
    ap = argparse.ArgumentParser()
    ap.add_argument("--model", default="qwen2.5-coder-security-v16-1-7b:latest")
    ap.add_argument("--k", type=int, default=3)
    ap.add_argument("--temp", type=float, default=0.6)
    ap.add_argument("--benches", nargs="*", default=None,
                    help="일부만 실행 (예: cybernative_benchmark diversevul_benchmark)")
    a = ap.parse_args()
    run(a.model, a.k, a.temp, a.benches)
