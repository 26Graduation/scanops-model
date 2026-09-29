"""ScanOps v2 — 학습 데이터 빌더 (V2_RUN_SPEC.md rev.6 §7·§8-2·§11).

`collect_files_v2.py` 가 뽑은 원시 샘플(파일 전문 + LINE 라벨)을 받아
  · §8-2 의 4096 토큰 예산 절차를 적용하고 (prompt_v2.build_input_within_budget)
  · §1 의 5줄 completion 을 만들고
  · §7 스키마 필드를 전부 채워
학습/평가용 jsonl 로 떨어뜨린다.

**프롬프트·포맷 조립은 전부 `prompt_v2.py` 에서 import 한다** (§11 단일 소스).
이 파일에 프롬프트 문자열을 다시 적지 않는다.

v1 `build_dataset.py` 는 FROZEN 이라 **수정하지 않고 import 만** 한다 (§11·§12).

출력 (train_qlora.py 가 TRAIN_SPLIT/VAL_SPLIT 환경변수로 그대로 읽는 이름):
  rebuild/data/train_v2line.jsonl
  rebuild/data/val_v2line.jsonl
  rebuild/data/test_v2line.jsonl
  rebuild/data/v2line_full.jsonl        ← §7 스키마 전체(감사·분석용, source 포함)

  ※ 파일명에 `line` 태그를 붙인 이유: `build_dataset_v2.py`/`train_v2.jsonl`/`val_v2.jsonl`
    이라는 이름을 2026-07-15 의 **다른 라운드**(PrimeVul+CleanVul 데이터 확장)가 이미 쓰고
    있었다. 사용자 확정에 따라 그 3개는 `_to_delete/v1_dataexp_round/` 로 옮겼고, 스크립트
    이름은 스펙 §11 대로 되찾았다. 다만 **데이터 파일명까지 같게 두면** 옮겨둔 옛 산출물과
    구분이 안 되고 `run_v2.sh` 가 옛 이름을 참조하고 있어, 데이터에는 태그를 유지한다.

실행:
  .venv/bin/python rebuild/build_dataset_v2.py rebuild/data/v2_samples_raw_pilot100.jsonl --tag pilot100
"""
from __future__ import annotations

import argparse
import hashlib
import json
import re
import sys
import time
from collections import Counter
from pathlib import Path

ROOT = Path(__file__).resolve().parent
sys.path.insert(0, str(ROOT))

import prompt_v2 as P  # noqa: E402   ← SINGLE SOURCE OF TRUTH (§11)

DATA = ROOT / "data"
OUT = ROOT / "out"

# v1 build_dataset.code_hash 와 동일 규칙 (분할 전 dedup — 누수 방지)
def code_hash(code: str) -> str:
    return hashlib.sha1(re.sub(r"\s+", " ", code).strip().lower().encode()).hexdigest()


# ── §10-1 "similarity>95% 제거" ──────────────────────────────────────────────
# audit 은 결과가 0 이길 요구한다("duplicates: … similarity>95% 0"). 즉 탐지가 아니라
# **파이프라인이 제거**해야 한다. exact 해시만으로는 안 잡히는 케이스가 실제로 있다:
# 같은 repo·같은 파일이 서로 다른 CVE 의 fix 커밋 두 개에 걸쳐 있으면, 두 시점의 파일 전문이
# 거의 같은데 해시는 다르다(PHASE 4 파일럿에서 4건 검출). 그대로 두면 사실상 같은 코드가
# train/test 로 갈라지는 누수가 된다.
def shingles(code: str, k: int = 5) -> set[str]:
    toks = re.sub(r"\s+", " ", code).strip().lower().split(" ")
    if len(toks) < k:
        return {" ".join(toks)}
    return {" ".join(toks[i:i + k]) for i in range(len(toks) - k + 1)}


def jaccard(a: set[str], b: set[str]) -> float:
    if not a or not b:
        return 0.0
    return len(a & b) / len(a | b)


def main() -> None:
    ap = argparse.ArgumentParser()
    ap.add_argument("raw", help="collect_files_v2.py 산출 jsonl")
    ap.add_argument("--tag", default="")
    ap.add_argument("--model", default="unsloth/Qwen3.5-9B")
    args = ap.parse_args()

    from transformers import AutoTokenizer
    tok = AutoTokenizer.from_pretrained(args.model)
    print(f"[build] tokenizer={args.model}  MAX_SEQ_LEN={P.MAX_SEQ_LEN} "
          f"COMPLETION_RESERVE={P.COMPLETION_RESERVE_TOKENS}", flush=True)

    rows = [json.loads(l) for l in Path(args.raw).open()]
    print(f"[build] 원시 샘플 {len(rows)}건", flush=True)

    # 순서 결정론 — 입력 파일이 병렬 수확 순서로 쓰였으므로, dedup 이 "누가 먼저 왔나"에
    # 좌우되지 않도록 여기서 고정 키로 정렬한다 (§5-0 과 같은 취지).
    rows.sort(key=lambda r: (r["cve_id"], r["repo"], r["file"], r["label"], r["fix_commit"]))

    stats = Counter()
    seen_hash: dict[str, str] = {}      # code_hash -> 먼저 차지한 샘플의 식별자
    # 근사중복 검사는 (repo, file, label) 버킷 안에서만 한다. 전수 O(n²) 는 비현실적이고,
    # 실제 위험(같은 파일의 다른 시점 버전)이 정확히 이 버킷 안에서 발생하기 때문이다.
    seen_sh: dict[tuple, list[tuple[str, set]]] = {}
    built = []
    t0 = time.time()

    for i, r in enumerate(rows, 1):
        # ── ④ 분할 전 dedup (v1 과 같은 위치·같은 규칙: 같은 코드가 train/test 로 갈라지는 누수 방지)
        h = code_hash(r["source"])
        key = f"{r['cve_id']}|{r['repo']}|{r['file']}|{r['label']}"
        if h in seen_hash:
            stats["drop_dup_exact"] += 1
            continue
        seen_hash[h] = key

        # ── §10-1 similarity>95% 제거 (다른 CVE 인데 사실상 같은 코드)
        bkey = (r["repo"], r["file"], r["label"])
        sh = shingles(r["source"])
        dup_of = None
        for prev_cve, prev_sh in seen_sh.get(bkey, ()):
            if prev_cve != r["cve_id"] and jaccard(sh, prev_sh) > 0.95:
                dup_of = prev_cve
                break
        if dup_of:
            stats["drop_dup_sim95"] += 1
            continue
        seen_sh.setdefault(bkey, []).append((r["cve_id"], sh))

        # ── §8-2 토큰 예산 (학습·추론·서빙이 같은 함수를 쓴다)
        b = P.build_input_within_budget(r["source"], r["language"], tok,
                                        line=r["line"] if r["label"] == "vuln" else 0)

        # ── §1 5줄 completion
        if r["label"] == "vuln":
            completion = P.vuln_completion_v2(
                r.get("cwe") or "", r.get("cwe_name") or "", r["line"],
                r.get("severity") or "UNKNOWN", r.get("cvss_str") or "UNKNOWN",
                r.get("reason") or "")
        else:
            completion = P.SAFE_COMPLETION_V2

        # 코드가 한 줄도 안 들어간 샘플은 버린다.
        # 실측 원인: minified/번들 JS (예: core-bundle/public/backend.7d12ce36.js) 는 파일이
        # 2~3 "줄"인데 한 줄이 거대해서 4096 예산에 **한 줄도** 못 들어간다 → 코드 블록이 빈
        # 프롬프트가 되어, 모델에게 "빈 코드에서 LINE 을 답하라"를 가르치는 꼴이 된다.
        # (F3 의 PATH_EXCLUDE 는 `.min.js`/`.bundle.js` 만 잡아서 해시 자산 파일명을 놓친다.)
        # positive 는 line_in_visible_context=False 라 이미 걸러지지만, negative(LINE=0)는
        # 그 규칙에 안 걸려서 학습셋까지 들어온다 — 여기서 라벨과 무관하게 막는다.
        if b["lines_kept"] == 0:
            stats["drop_empty_code"] += 1
            continue

        ctoks = P.count_completion_tokens(completion, tok)
        overflow = ctoks > P.COMPLETION_RESERVE_TOKENS
        if overflow:
            stats["format_overflow"] += 1

        rec = {
            # ── §7 스키마 ────────────────────────────────────────────────
            "label": r["label"],
            "cve_id": r["cve_id"],
            "repo": r["repo"],
            "fix_commit": r["fix_commit"],
            "file": r["file"],
            "language": r["language"],
            "lang_group": r["lang_group"],
            "cwe": r.get("cwe"),
            "line": r["line"],
            "line_source": r["line_source"],
            "line_selection_rule": r["line_selection_rule"],
            "num_vulnerabilities_in_diff": r["num_vulnerabilities_in_diff"],
            "selected_vulnerability_rule": r["selected_vulnerability_rule"],
            "cvss": r["cvss"],
            "cvss_present": r["cvss_present"],
            "cvss_source": r["cvss_source"],
            "cvss_version": r["cvss_version"],
            "file_lines_total": b["file_lines_total"],
            "prompt_tokens": b["prompt_tokens"],
            "code_tokens": b["code_tokens"],
            "input_tokens": b["input_tokens"],
            "completion_reserve_tokens": b["completion_reserve_tokens"],
            "max_sequence_tokens": b["max_sequence_tokens"],
            "truncated": b["truncated"],
            "line_in_visible_context": b["line_in_visible_context"],
            "line_numbering_format": b["line_numbering_format"],
            "split": r["split"],
            "test_cohort_source": r["test_cohort_source"],
            # ── 계측/감사용 추가 필드 ──────────────────────────────────────
            "completion_tokens": ctoks,
            "format_overflow": overflow,
            "lines_kept": b["lines_kept"],
            "line_text": r.get("line_text"),
            "line_text_matches_file": r.get("line_text_matches_file"),
            # 학습에 실제로 들어가는 두 필드
            "prompt": b["prompt"],
            "completion": completion,
            # audit 이 dedup·line 대조에 쓰는 원본 (학습에는 안 들어간다)
            "source": r["source"],
        }
        built.append(rec)
        stats[f"kept_{r['label']}"] += 1
        if i % 200 == 0:
            print(f"[build] {i}/{len(rows)} ({time.time()-t0:.0f}s)", flush=True)

    # ── format_overflow 샘플은 학습 데이터에서 버린다 (§8-2). 평가에서는 안 버린다.
    tag = f"_{args.tag}" if args.tag else ""
    full_path = DATA / f"v2line_full{tag}.jsonl"
    with full_path.open("w") as f:
        for r in built:
            f.write(json.dumps(r, ensure_ascii=False) + "\n")

    n_written = Counter()
    n_dropped = Counter()
    for sp in ("train", "val", "test"):
        p = DATA / f"{sp}_v2line{tag}.jsonl"
        with p.open("w") as f:
            for r in built:
                if r["split"] != sp:
                    continue
                # 학습셋(train/val)에서만 버린다 — 평가(test)는 버리지 않는다 (§8-2).
                #  · format_overflow: completion 이 예약 128 토큰을 넘는 샘플
                #  · line_in_visible_context=false: 결정론적으로 자른 창 밖으로 정답 LINE 이
                #    나간 positive 샘플. 모델이 볼 수 없는 답을 학습시키는 셈이라 버린다.
                #    (정답이 보이도록 창을 다시 고르지 않는다 — 그건 §8-2 가 금지한 누수다.
                #     "정답과 무관하게 정해진 창에 우연히 들어왔는지만 확인"하고 버린다.)
                if sp in ("train", "val"):
                    if r["format_overflow"]:
                        n_dropped[f"{sp}_format_overflow"] += 1
                        continue
                    if r["label"] == "vuln" and not r["line_in_visible_context"]:
                        n_dropped[f"{sp}_line_invisible"] += 1
                        continue
                f.write(json.dumps({
                    "prompt": r["prompt"], "completion": r["completion"],
                    "meta": {k: r[k] for k in
                             ("cve_id", "repo", "file", "label", "language", "lang_group",
                              "cwe", "line", "truncated", "line_in_visible_context",
                              "cvss_present", "test_cohort_source")},
                }, ensure_ascii=False) + "\n")
                n_written[sp] += 1

    rep = {
        "raw": args.raw, "tag": args.tag, "n_raw": len(rows), "n_built": len(built),
        "stats": dict(stats),
        "written": dict(n_written),
        "dropped_from_training": dict(n_dropped),
        "truncation_rate_pct": round(100 * sum(1 for r in built if r["truncated"])
                                     / max(1, len(built)), 2),
        "completion_tokens": {
            "max": max((r["completion_tokens"] for r in built), default=0),
            "mean": round(sum(r["completion_tokens"] for r in built) / max(1, len(built)), 1),
            "reserve": P.COMPLETION_RESERVE_TOKENS,
        },
        "elapsed_sec": round(time.time() - t0, 1),
    }
    (OUT / f"v2_build_report{tag}.json").write_text(json.dumps(rep, ensure_ascii=False, indent=2))
    print(json.dumps(rep, ensure_ascii=False, indent=2))
    print(f"-> {full_path}")


if __name__ == "__main__":
    main()
