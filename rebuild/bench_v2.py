"""ScanOps v2 — juice-shop 레포 벤치 (V2_RUN_SPEC.md rev.6 §8·§8-3·§8-4·§9).

**`bench_common.py` 는 이번 라운드에 아예 건드리지 않는다** (§11 완전 동결). 평가 로직은 전부
여기에 새로 쓴다. 프롬프트·포맷·4096 예산은 `prompt_v2.py` 에서 import 한다 (§11 단일 소스).

무엇을 재나:
  ① exact-line 사다리 — exact / ±1 / ±3 / ±N   (주지표는 **exact-line, 오차 0**)
     · 전체 / visible-only / invisible 로 **반드시 나눠서** 보고한다 (§8-3)
  ② 파일 경보율 — v1 실측 44.75% 와 Δ 병기 (§9)
  ③ truncation 계측 — 257 파일 전체에 대해 (§8-2)

gold LINE 의 출처 (§8-4): `rebuild/data/repo_bench/juice-shop_truth.jsonl` 을 **그대로 재사용**한다.
새로 만들지 않는다. v1 의 0/36 측정이 쓴 바로 그 파일이다.
  ※ 스펙 §8-4 는 "이 파일의 gold `line`" 이라고 적었지만 실제 필드명은 **`sink_line`** 이다
    (PHASE 0 에서 파일을 열어 확인). 값의 의미는 같다.

스캔 범위: v1 과 동일한 SCOPE(`repo_bench_scan.py:56-62`, .ts 257 파일)를 쓴다 — ②의 44.75% 와
직접 비교하려면 분모가 같아야 하기 때문이다. 그래서 truth 36건 중 SCOPE 밖 파일(.sol/.yml/.tf)에
있는 항목은 자동으로 미탐이 된다. v1 도 같은 조건이었다(`truth_in_scope_scored=33`). 헤드라인은
스펙대로 X/36 으로 적고, 참고로 X/33(in-scope)도 같이 남긴다.

그래프는 쓰지 않는다 (§12 "그래프 쪽 변경 없음" + 이번 라운드는 순수 LLM 파일단위 판정).

실행:
  # 1) llama-server 를 띄운다 (v1과 동일 스택, LoRA 필수)
  # 2) scan → score
  .venv/bin/python rebuild/bench_v2.py scan  --tag v2
  .venv/bin/python rebuild/bench_v2.py score --tag v2
"""
from __future__ import annotations

import argparse
import json
import os
import sys
import time
from collections import Counter, defaultdict
from concurrent.futures import ThreadPoolExecutor
from pathlib import Path
from statistics import median

ROOT = Path(__file__).resolve().parent
sys.path.insert(0, str(ROOT))

import prompt_v2 as P  # noqa: E402   ← SINGLE SOURCE OF TRUTH (§11)

OUT = ROOT / "out"
DATA = ROOT / "data"
TRUTH = DATA / "repo_bench" / "juice-shop_truth.jsonl"
LLAMA = os.getenv("LLAMA_SERVER_URL", "http://127.0.0.1:8080")
REPO_DIR = Path(os.getenv("JUICE_SHOP_DIR", "/private/tmp/scanops_repobench/juice-shop"))

# v1 `repo_bench_scan.py:56-62` 의 SCOPE 를 그대로 옮겨 적었다 (그 파일은 건드리지 않는다).
# 분모(257 파일)가 같아야 ②의 v1 44.75% 와 비교가 성립한다.
SCOPE = {
    "include": ["routes/**/*.ts", "lib/**/*.ts", "models/**/*.ts",
                "server.ts", "app.ts", "frontend/src/app/**/*.ts"],
    "exclude_suffix": [".spec.ts", ".d.ts"],
    "lang": "TypeScript",
}


def scan_files() -> list[tuple[str, str]]:
    """(상대경로, 내용) 목록. 정렬 고정 — v1 과 동일 규칙."""
    seen: dict[str, Path] = {}
    for pat in SCOPE["include"]:
        for p in sorted(REPO_DIR.glob(pat)):
            if not p.is_file():
                continue
            rel = str(p.relative_to(REPO_DIR))
            if any(rel.endswith(s) for s in SCOPE["exclude_suffix"]):
                continue
            seen[rel] = p
    out = []
    for rel in sorted(seen):
        try:
            out.append((rel, seen[rel].read_text(encoding="utf-8", errors="replace")))
        except OSError:
            continue
    return out


# ── scan ─────────────────────────────────────────────────────────────────────
def cmd_scan(tag: str, workers: int, limit: int = 0) -> None:
    """llama-server 로 파일 단위 판정. **재개 가능** (같은 명령을 다시 돌리면 이어서 한다)."""
    import requests
    from transformers import AutoTokenizer

    tok = AutoTokenizer.from_pretrained(os.getenv("V2_TOKENIZER", "unsloth/Qwen3.5-9B"))
    out_path = OUT / f"bench_v2_{tag}_juice-shop_raw.jsonl"
    done = set()
    if out_path.exists():
        done = {json.loads(l)["file"] for l in out_path.open()}
        print(f"재개: {len(done)}건 완료")

    files = scan_files()
    print(f"[scan] SCOPE 파일 {len(files)}개 (v1 실측 257) / 남은 {len(files)-len(done)}개", flush=True)
    todo = [(rel, code) for rel, code in files if rel not in done]
    if limit:
        todo = todo[:limit]
        print(f"[scan] --limit {limit} 적용 (스모크 테스트용). 전체 스캔이 아니다.", flush=True)
    t_all = time.time()

    def work(item):
        rel, code = item
        t0 = time.time()
        # §8-2 절차를 학습 때와 **같은 함수**로 적용한다. 평가에서는 잘려도 버리지 않는다.
        b = P.build_input_within_budget(code, SCOPE["lang"], tok, line=None)
        gen = P.build_generation_prompt(b["prompt"], tok)
        r = requests.post(f"{LLAMA}/completion", json={
            "prompt": gen, "n_predict": P.COMPLETION_RESERVE_TOKENS,
            "temperature": 0.0, "stop": ["<|im_end|>"]}, timeout=900)
        r.raise_for_status()
        raw = r.json().get("content", "")
        parsed = P.parse_output_v2(raw)
        return {
            "file": rel, "chars": len(code),
            "file_lines_total": b["file_lines_total"], "lines_kept": b["lines_kept"],
            "input_tokens": b["input_tokens"], "truncated": b["truncated"],
            "pred_label": parsed["label"], "pred_line": parsed["line"],
            "pred_cwe": parsed["cwe"], "pred_severity": parsed["severity"],
            "format_inconsistent": parsed["format_inconsistent"],
            "raw": raw[:800], "elapsed": round(time.time() - t0, 2),
        }

    with out_path.open("a") as f, ThreadPoolExecutor(max_workers=workers) as ex:
        for i, rec in enumerate(ex.map(work, todo), 1):
            f.write(json.dumps(rec, ensure_ascii=False) + "\n")
            f.flush()
            if i % 10 == 0:
                print(f"  {i}/{len(todo)}  {time.time()-t_all:.0f}s", flush=True)
    print(f"[scan] 완료 -> {out_path}  ({time.time()-t_all:.0f}s)")


# ── ±N 확정 (§8-1) ───────────────────────────────────────────────────────────
def compute_N(samples_path: Path) -> dict:
    """§8-1 — 같은 CVE+파일 안에서 삭제줄이 2개 이상인 그룹만 모아
    **연속 삭제줄 간격의 중앙값**을 구해 반올림한 값을 N 으로 확정한다.

    R4 8건 파일럿(중앙값 3.5)은 표본이 너무 작아 그대로 쓰지 않는다 — 전체 수확 데이터로
    재계산해서 확정하고, 확정 후에는 바꾸지 않는다 (사전등록).
    """
    gaps: list[int] = []
    n_groups = 0
    for line in samples_path.open():
        r = json.loads(line)
        dl = r.get("deleted_lines_all")
        if not dl or len(dl) < 2:
            continue
        n_groups += 1
        s = sorted(set(dl))
        gaps.extend(b - a for a, b in zip(s, s[1:]))
    if not gaps:
        return {"N": None, "n_groups": 0, "n_gaps": 0, "median_gap": None,
                "note": "간격 표본 0 — deleted_lines_all 이 수확에 기록되지 않았다"}
    m = median(gaps)
    return {"N": int(round(m)), "n_groups": n_groups, "n_gaps": len(gaps),
            "median_gap": m, "mean_gap": round(sum(gaps) / len(gaps), 1),
            "max_gap": max(gaps)}


# ── score ────────────────────────────────────────────────────────────────────
V1_FLAG_RATE = 0.4475          # `rebuild/out/repo_bench_juice-shop_metrics.json` arms.S1.flag_rate
V1_EXACT_LINE = 0              # v1 은 구조적으로 라인을 낼 수 없어 0/36


def cmd_score(tag: str, N: int | None) -> None:
    raw_path = OUT / f"bench_v2_{tag}_juice-shop_raw.jsonl"
    if not raw_path.exists():
        print(f"[BLOCKED] scan 산출물 없음: {raw_path}")
        sys.exit(2)
    preds = {json.loads(l)["file"]: json.loads(l) for l in raw_path.open()}

    truth = [json.loads(l) for l in TRUTH.open()]
    code_items = [t for t in truth if t.get("is_code_file")]
    in_scope = [t for t in code_items if t["sink_file"] in preds]

    # ── ③ truncation 계측 (§8-2)
    n_files = len(preds)
    n_trunc = sum(1 for p in preds.values() if p["truncated"])
    trunc = {"total_files_scanned": n_files,
             "le_4096_tokens": n_files - n_trunc, "truncated": n_trunc,
             "truncation_rate_pct": round(100 * n_trunc / max(1, n_files), 2)}

    # ── ② 파일 경보율 (§9). v1 과 같은 분모(SCOPE 파일 전체)
    n_vuln = sum(1 for p in preds.values() if p["pred_label"] == "vuln")
    n_parse_fail = sum(1 for p in preds.values() if p["pred_label"] == "parse_fail")
    n_inconsistent = sum(1 for p in preds.values() if p["format_inconsistent"])
    flag_rate = n_vuln / max(1, n_files)
    alarm = {
        "n_vuln_files": n_vuln, "n_files": n_files,
        "flag_rate": round(flag_rate, 4),
        "v1_flag_rate": V1_FLAG_RATE,
        "delta_pp": round(100 * (flag_rate - V1_FLAG_RATE), 2),
        "parse_fail": n_parse_fail, "format_inconsistent": n_inconsistent,
    }

    # ── ① exact-line 사다리 (§8) + visible/invisible 분리 (§8-3)
    ladders = [("exact", 0), ("pm1", 1), ("pm3", 3)]
    if N is not None:
        ladders.append((f"pmN(N={N})", N))

    def is_visible(t) -> bool:
        """정답 LINE 이 최종 입력 context 에 **온전히** 들어와 있었는가 (§8-2 엄격 기준).

        절단은 줄 경계에서만 하므로 정답 줄은 온전히 있거나 아예 없다 — 한 글자만 잘리는
        상태가 존재하지 않는다. SCOPE 밖 파일(스캔조차 안 된 것)은 invisible 로 센다.
        """
        p = preds.get(t["sink_file"])
        if p is None:
            return False
        return 1 <= t["sink_line"] <= p["lines_kept"]

    def hit(t, tol: int) -> bool:
        p = preds.get(t["sink_file"])
        if p is None or p["pred_label"] != "vuln" or p["pred_line"] is None:
            return False
        if p["format_inconsistent"]:
            return False          # §7-1 — 형식 위반 출력은 정오답 계산에서 뺀다
        return abs(p["pred_line"] - t["sink_line"]) <= tol

    vis = [t for t in code_items if is_visible(t)]
    invis = [t for t in code_items if not is_visible(t)]

    ladder_out = {}
    for name, tol in ladders:
        ladder_out[name] = {
            "all": f"{sum(1 for t in code_items if hit(t, tol))}/{len(code_items)}",
            "visible_only": f"{sum(1 for t in vis if hit(t, tol))}/{len(vis)}",
            "invisible": f"{sum(1 for t in invis if hit(t, tol))}/{len(invis)}",
            "in_scope": f"{sum(1 for t in in_scope if hit(t, tol))}/{len(in_scope)}",
        }

    exact_all = sum(1 for t in code_items if hit(t, 0))

    # ── 사전등록 판정 (§9). 결과를 보고 기준을 바꾸지 않는다.
    verdict = {
        "①_exact_line_gt_0": {"value": exact_all, "threshold": "> 0",
                              "pass": exact_all > 0, "v1": V1_EXACT_LINE},
        "②_flag_rate_lt_45pct": {"value": round(100 * flag_rate, 2), "threshold": "< 45.00",
                                 "pass": flag_rate < 0.45,
                                 "v1": round(100 * V1_FLAG_RATE, 2),
                                 "delta_pp": alarm["delta_pp"],
                                 "_주의": "통과 여부와 '의미 있는 개선인가'는 다른 문장으로 적는다 (§9)"},
        "③_internal_test_auc": {"value": None, "threshold": ">= 0.855",
                                "pass": None,
                                "_note": "score_logprob.py 로 별도 산출 후 채운다 (§9-1)"},
    }
    rep = {
        "tag": tag, "repo": "juice-shop",
        "gold_source": str(TRUTH),
        "gold_field": "sink_line (스펙 §8-4 의 'line' 은 실제 필드명이 sink_line)",
        "truth_total": len(truth), "truth_code_items": len(code_items),
        "truth_in_scope": len(in_scope),
        "truth_visible": len(vis), "truth_invisible": len(invis),
        "truncation": trunc,
        "file_alarm": alarm,
        "exact_line_ladder": ladder_out,
        "verdict_prereg": verdict,
        "_입력표현": "파일 단위 입력 — 최대 4096-token context (파일 '전체'가 아니다, §12)",
    }
    p = OUT / f"bench_v2_{tag}_juice-shop_metrics.json"
    p.write_text(json.dumps(rep, ensure_ascii=False, indent=2))
    print(json.dumps(rep, ensure_ascii=False, indent=2))
    print(f"-> {p}")


def main() -> None:
    ap = argparse.ArgumentParser()
    ap.add_argument("cmd", choices=["scan", "score", "computeN"])
    ap.add_argument("--tag", default="v2")
    ap.add_argument("--workers", type=int, default=2)
    ap.add_argument("--N", type=int, default=None, help="§8-1 로 확정한 ±N")
    ap.add_argument("--limit", type=int, default=0, help="스모크 테스트용 파일 수 제한")
    ap.add_argument("--samples", default=str(DATA / "v2_samples_raw_all.jsonl"))
    a = ap.parse_args()
    if a.cmd == "scan":
        cmd_scan(a.tag, a.workers, a.limit)
    elif a.cmd == "computeN":
        r = compute_N(Path(a.samples))
        (OUT / "v2_pmN.json").write_text(json.dumps(r, ensure_ascii=False, indent=2))
        print(json.dumps(r, ensure_ascii=False, indent=2))
    else:
        cmd_score(a.tag, a.N)


if __name__ == "__main__":
    main()
