"""
Ablation Phase 1 — 신호 추출 (graph 1회 계산 + 캐시 LLM 점수 결합)
==================================================================
목적: "LLM 탐지기를 빼고 Graph 단독으로 전환해도 되는가"를 재기 위한 raw 신호를
      케이스당 딱 1회만 만들어 JSONL로 남긴다. arm 4개는 이 파일을 읽어
      후처리 산술로만 만든다(재계산 금지).

원칙:
  - 기존 모듈은 **import만** 한다. 한 줄도 수정하지 않는다.
  - LLM 점수는 캐시된 logprob에서 **읽어오기만** 한다. 재채점·GPU 사용 없음.
  - append 모드로 케이스마다 즉시 기록. 이미 기록된 case_id는 건너뛴다(재개 가능).

출력: out/ablation_raw_cleanvul_v2_{report,tune}.jsonl
  {case_id, pair_id, lang, label, llm_score, graph_verdict, graph_strong,
   llm_score_v3s42, graph_supported, graph_category, graph_reason}

  · llm_score       = 주 모델 v1(rebuild/out/adapter)의 캐시 logprob score
  · llm_score_v3s42 = 부 모델 v3s42의 캐시 logprob score (사양 스키마 외 추가 필드)
  · graph_supported = multi_graph._lang_key()가 None이 아닌가 (C/C++는 False)
  · graph_strong    = multi_graph의 고신뢰 safe 표식. java_graph 경로는 이 필드를
                      애초에 만들지 않으므로 항상 False로 기록된다(§5에 기재).

실행: python rebuild/ablation_graph_only.py            # 두 split 모두
      python rebuild/ablation_graph_only.py report     # 하나만
"""
from __future__ import annotations

import json
import re
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent          # rebuild/
REPO = ROOT.parent                              # scanops-model/
sys.path.insert(0, str(REPO))

from scanops.core.multi_graph import _lang_key, analyze  # noqa: E402 (읽기 전용)

OUT = ROOT / "out"

# 프롬프트 본문에서 코드 블록만 떼어낸다.
# 형식: "Analyze the following X code ...\n\n```X\n<code>\n```\n\nRespond in exactly this format:"
CODE_RE = re.compile(r"```[^\n]*\n(.*)\n```\s*\n\s*Respond in exactly this format:", re.S)


def case_id(meta: dict) -> str:
    """벤치 데이터에 case_id 필드가 없어 (pair_id, label)로 대체한다.
    유일성은 ablation_preflight.py 0-2에서 실증했다(중복 0건)."""
    return f"{meta['pair_id']}|{meta['label']}"


def load_jsonl(p: Path) -> list[dict]:
    return [json.loads(l) for l in p.open()]


def extract_code(prompt: str) -> str | None:
    m = CODE_RE.search(prompt)
    return m.group(1) if m else None


def run_split(split: str) -> dict:
    bench = load_jsonl(ROOT / "data" / f"cleanvul_v2_{split}.jsonl")

    # ── 캐시된 LLM 점수 적재 (읽기 전용) ──────────────────────────────────
    lp = {}
    for tag in ("v1", "v3s42"):
        recs = load_jsonl(OUT / f"{tag}_logprob_cleanvul_v2_{split}.jsonl")
        lp[tag] = {case_id(r["meta"]): r["score"] for r in recs}

    out_path = OUT / f"ablation_raw_cleanvul_v2_{split}.jsonl"

    # ── 재개: 이미 기록된 case_id는 건너뛴다 ──────────────────────────────
    done: set[str] = set()
    if out_path.exists():
        for line in out_path.open():
            line = line.strip()
            if line:
                done.add(json.loads(line)["case_id"])

    stats = {"split": split, "n_bench": len(bench), "n_resumed_skip": len(done),
             "n_written": 0, "n_code_extract_fail": 0,
             "n_llm_miss_v1": 0, "n_llm_miss_v3s42": 0,
             "verdicts": {}, "verdicts_supported_only": {}}

    with out_path.open("a") as f:
        for rec in bench:
            meta = rec["meta"]
            cid = case_id(meta)
            if cid in done:
                continue

            code = extract_code(rec["prompt"])
            if code is None:
                stats["n_code_extract_fail"] += 1
                # 코드를 못 떼면 graph를 태울 수 없다 — 억지로 채우지 않고 기록만 한다.
                code = ""

            lang = meta["language"]
            supported = _lang_key(lang) is not None
            g = analyze(code, lang) if code else {"verdict": "unknown", "category": "?",
                                                  "reason": "코드 추출 실패"}

            s1 = lp["v1"].get(cid)
            s3 = lp["v3s42"].get(cid)
            if s1 is None:
                stats["n_llm_miss_v1"] += 1
            if s3 is None:
                stats["n_llm_miss_v3s42"] += 1

            row = {
                "case_id": cid,
                "pair_id": meta["pair_id"],
                "lang": lang,
                "lang_group": meta["lang_group"],
                "label": meta["label"],
                "llm_score": s1,
                "llm_score_v3s42": s3,
                "graph_verdict": g["verdict"],
                "graph_strong": bool(g.get("strong", False)),
                "graph_supported": supported,
                "graph_category": g.get("category", ""),
                "graph_reason": g.get("reason", ""),
            }
            f.write(json.dumps(row, ensure_ascii=False) + "\n")
            f.flush()                              # 케이스마다 즉시 기록(중단 대비)
            stats["n_written"] += 1

            v = g["verdict"]
            stats["verdicts"][v] = stats["verdicts"].get(v, 0) + 1
            if supported:
                stats["verdicts_supported_only"][v] = stats["verdicts_supported_only"].get(v, 0) + 1

    # 최종 파일 검증
    rows = load_jsonl(out_path)
    stats["n_final_rows"] = len(rows)
    stats["n_final_unique"] = len({r["case_id"] for r in rows})
    stats["complete"] = stats["n_final_unique"] == len(bench)
    return stats


def main() -> None:
    targets = sys.argv[1:] or ["report", "tune"]
    all_stats = [run_split(s) for s in targets]
    (OUT / "ablation_raw_stats.json").write_text(
        json.dumps(all_stats, ensure_ascii=False, indent=2))
    print(json.dumps(all_stats, ensure_ascii=False, indent=2))


if __name__ == "__main__":
    main()
