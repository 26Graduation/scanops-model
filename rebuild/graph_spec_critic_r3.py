"""GRAPH-SPEC 3라운드 STEP 8 (§12-4 유지) — critic 3분류 + evidence 검증 + 재현성 측정.

2라운드 `graph_spec_critic_r2.py` 를 파일명·출력경로·온도만 바꿔 분리한 것이다.
판정 규칙(TRUE/FALSE/UNCERTAIN, evidence 검증, 90% 경고)은 §12-4 그대로다.

추가: temperature=0 고정, RUNTAG 로 동일 입력 반복 실행 → 실행 간 판정 일치율 측정.

1라운드 `graph_spec_critic.py` 는 손대지 않는다. 이 파일이 2라운드용이다.

§12-4 가 요구하는 것:
  1. evidence 라인 == finding sink 라인. 넘기기 전에 검증하고 불일치 건수를 기록한다.
     → `graph_spec_evidence_audit_r2.validate_evidence()` 를 호출 직전에 건다.
       불일치 finding 은 **LLM 에 보내지 않고 격리**하고 `evidence_mismatch` 로 남긴다.
  2. 출력은 TRUE / FALSE / UNCERTAIN 3분류.
  3. 채점에는 TRUE 만. **UNCERTAIN 은 삭제하지 않고 보존**하고 두 시나리오를 모두 기록한다.
  4. FALSE 에는 근거로 삼은 라인과 이유를 반드시 남긴다.
  5. 한 arm 의 90% 이상을 제거하면 경고를 기록한다.

실행: python rebuild/graph_spec_critic_r2.py juice-shop <repo_dir> R2 R3
출력: rebuild/out/graph_spec_critic_r2_{arm}_{repo}.json
      rebuild/out/graph_spec_critic_raw_r2_{repo}.jsonl   (LLM 원본, checkpoint)
"""
from __future__ import annotations

import json
import os
import re
import sys
import threading
import time
from concurrent.futures import ThreadPoolExecutor
from datetime import datetime, timedelta, timezone
from pathlib import Path

ROOT = Path(__file__).resolve().parent
REPO = ROOT.parent
OUT = ROOT / "out"
sys.path.insert(0, str(ROOT))

from graph_spec_critic import dedupe, fmt_finding  # noqa: E402
from graph_spec_evidence_audit_r2 import validate_evidence  # noqa: E402

KST = timezone(timedelta(hours=9))
CALL_CAP = int(os.getenv("GCRITIC3_CALL_CAP", "4000"))       # 로컬 모델은 비용 제약 없음
# GRAPH_RUN_SPEC.md §20: "소스코드 외부 전송 0" 요구사항 위반 지적으로 로컬 모델 전환.
BATCH = int(os.getenv("GCRITIC3_BATCH", "4"))                # 55→6 처럼 로컬 모델 배치 축소
WORKERS = int(os.getenv("GCRITIC3_WORKERS", "1"))            # llama-server --parallel 1 과 맞춤
MODEL = os.getenv("GCRITIC3_MODEL", "qwen3.5-9b-local")
LLAMA = os.getenv("LLAMA_SERVER_URL", "http://127.0.0.1:8080")
CHATML_TMPL = "<|im_start|>user\n{p}<|im_end|>\n<|im_start|>assistant\n<think>\n\n</think>\n\n"
# 로컬 모델은 temperature=0 이 실제로 적용된다(claude-opus-5 는 거부했었다 — §20-2).
TEMPERATURE_SETTING = "0.0 (로컬 llama-server, 실제 적용됨)"
TEMPERATURE_API_ERROR = None
RUNTAG = os.getenv("GCRITIC3_RUNTAG", "a")             # 동일 입력 반복 실행 식별자
REMOVAL_WARN = 0.90        # §12-4-5


def _parses_as_json_array(text: str) -> bool:
    txt = re.sub(r"<think>.*?</think>", "", text, flags=re.S).strip()
    if txt.startswith("```"):
        txt = re.sub(r"^```[a-z]*\n", "", txt)
        txt = re.sub(r"\n```$", "", txt)
    lb, rb = txt.find("["), txt.rfind("]")
    if lb == -1 or rb == -1 or rb <= lb:
        return False
    try:
        arr = json.loads(txt[lb:rb + 1])
        return isinstance(arr, list) and len(arr) > 0
    except Exception:
        return False


def _call_local(prompt: str, n_items: int) -> tuple[str, dict]:
    """실패 시 n_predict 를 늘려 최대 3회 재시도(graph_spec_llm.py 와 동일 패턴)."""
    import requests
    text, rj = "", {}
    for attempt in range(3):
        r = requests.post(f"{LLAMA}/completion", json={
            "prompt": CHATML_TMPL.format(p=prompt),
            "n_predict": 250 * max(1, n_items) * (attempt + 1),
            "temperature": 0.0, "stop": ["<|im_end|>"]}, timeout=600)
        r.raise_for_status()
        rj = r.json()
        text = rj.get("content", "")
        if _parses_as_json_array(text):
            break
    return text, rj

SYSTEM = """You are auditing candidate taint-flow findings produced by a static analyser (Joern) on a real codebase.

For each finding you get: the vulnerability category and CWE, the flow the analyser found (source node -> intermediate nodes -> sink node, with file and line for each), and the source code around the sink and the source.

Decide whether the finding is a REAL vulnerability AT THE SINK LINE SHOWN.

Judge it as a security reviewer would:
- Is the data reaching the sink actually attacker-controlled? A hardcoded literal, a config constant, an internal enum, or a value the analyser merely passed through is not.
- Is the sink genuinely dangerous for that CWE at this call site?
- Is there neutralisation on the path (parameterised query, encoding, allow-list, type coercion, escaping)?
- Judge only what the shown code supports.

Use THREE verdicts. Do not collapse them:
  "TRUE"      — the evidence shown supports a real vulnerability at this sink line.
  "FALSE"     — the evidence shown positively rules it out (you can point at the line that rules it out).
  "UNCERTAIN" — you cannot tell from the shown code. Missing context, unresolved call, ambiguous data origin.

UNCERTAIN is a first-class answer, not a soft FALSE. Use it whenever you would otherwise guess.
Only answer FALSE when you can name the specific line that makes it safe.

Answer with ONE JSON array, no prose, no markdown fence. One object per finding, same order:
{"id": <int, echo the input id>,
 "verdict": "TRUE" | "FALSE" | "UNCERTAIN",
 "confidence": "high" | "med" | "low",
 "basis_line": <int — the line number your verdict rests on; REQUIRED when verdict is FALSE>,
 "reason": "<max 25 words>"}"""

USER_TMPL = """Repository language: {lang}
Judge each finding below.

{items}

Return the JSON array now."""


def main(repo: str, repo_dir: Path, arms: list[str]) -> None:
    raw_path = OUT / f"graph_spec_critic_raw_r3_{RUNTAG}_{repo}.jsonl"

    done: set[str] = set()
    if raw_path.exists():
        for line in raw_path.open():
            try:
                r = json.loads(line)
                done.add(f"{r['arm']}#{r['batch']}")
            except Exception:
                pass

    lock = threading.Lock()
    budget = {"calls": 0, "in_tok": 0, "out_tok": 0}
    t0 = time.time()
    summary = {"repo": repo, "critic_model": MODEL,
               "temperature_setting": TEMPERATURE_SETTING,
               "temperature_api_error": TEMPERATURE_API_ERROR,
               "sampling_note": "thinking prefill로 억제. temperature=0 실제 적용(로컬).",
               "run_tag": RUNTAG, "external_api": False,
               "api_provider": "local llama-server (Qwen3.5-9B, 어댑터 없음, 127.0.0.1)",
               "batch_size": BATCH,
               "critic_call_cap": CALL_CAP, "verdicts": "TRUE/FALSE/UNCERTAIN (§12-4-2)",
               "arms": {}}

    for arm in arms:
        ap = OUT / f"graph_spec_arm_{arm}_{repo}.json"
        if not ap.exists():
            summary["arms"][arm] = {"error": f"arm raw 없음: {ap}"}
            continue
        d = json.loads(ap.read_text())
        fi = [x for x in (d.get("result") or {}).get("findings", []) if not x.get("sanitized")]
        uniq, dstat = dedupe(fi)

        # ── §12-4-1 evidence 라인 검증: 통과분만 LLM 에 보낸다 ──────────────────
        sendable, quarantined = [], []
        for f in uniq:
            rendered = fmt_finding(f, repo_dir)
            ok, diag = validate_evidence(f, rendered)
            if ok:
                sendable.append(f)
            else:
                quarantined.append({"file": f["file"], "line": f.get("line"),
                                    "category": f["category"], "problems": diag["problems"]})
        print(f"[{arm}] 고유 {len(uniq)}건 → evidence 검증 통과 {len(sendable)} / "
              f"불일치 격리 {len(quarantined)}", flush=True)

        batches = [sendable[i:i + BATCH] for i in range(0, len(sendable), BATCH)]
        verdicts: dict[int, dict] = {}
        skipped: list[int] = []

        def work(bi: int) -> None:
            key = f"{arm}#{bi}"
            if key in done:
                return
            with lock:
                if budget["calls"] >= CALL_CAP:
                    skipped.append(bi)
                    return
                budget["calls"] += 1
            body = "\n\n".join(fmt_finding(f, repo_dir) for f in batches[bi])
            user = USER_TMPL.format(lang="TypeScript/JavaScript", items=body)
            try:
                text, rj = _call_local(SYSTEM + "\n\n" + user, len(batches[bi]))
                with lock:
                    budget["in_tok"] += rj.get("tokens_evaluated", 0)
                    budget["out_tok"] += rj.get("tokens_predicted", 0)
                    with raw_path.open("a") as fh:
                        fh.write(json.dumps({"arm": arm, "batch": bi, "model": MODEL,
                                             "uids": [f["_uid"] for f in batches[bi]],
                                             "raw": text}, ensure_ascii=False) + "\n")
                    print(f"  [{arm}] batch {bi+1}/{len(batches)} ok", flush=True)
            except Exception as e:
                with lock:
                    skipped.append(bi)
                    print(f"  [{arm}] batch {bi+1} ERROR {str(e)[:150]}", flush=True)

        def collect() -> None:
            verdicts.clear()
            if not raw_path.exists():
                return
            for line in raw_path.open():
                r = json.loads(line)
                if r["arm"] != arm:
                    continue
                txt = re.sub(r"<think>.*?</think>", "", r["raw"], flags=re.S).strip()
                if txt.startswith("```"):
                    txt = re.sub(r"^```[a-z]*\n", "", txt)
                    txt = re.sub(r"\n```$", "", txt)
                lb, rb = txt.find("["), txt.rfind("]")
                if lb == -1 or rb == -1 or rb <= lb:
                    continue
                try:
                    arr = json.loads(txt[lb:rb + 1])
                except Exception:
                    continue
                for o in arr:
                    if isinstance(o, dict) and "id" in o:
                        verdicts[o["id"]] = o

        with ThreadPoolExecutor(max_workers=WORKERS) as ex:
            list(ex.map(work, range(len(batches))))
        collect()

        # 미판정 보충 패스 — LLM 이 배치 안 일부 id 를 빠뜨리는 경우
        missing = [f for f in sendable if f["_uid"] not in verdicts]
        n_fill = 0
        if missing:
            fb = max(4, BATCH // 2)
            fbatches = [missing[i:i + fb] for i in range(0, len(missing), fb)]
            print(f"  [{arm}] 미판정 {len(missing)}건 → 보충 {len(fbatches)}회", flush=True)

            def fill(fi_: int) -> None:
                if f"{arm}#fill{fi_}" in done:
                    return
                with lock:
                    if budget["calls"] >= CALL_CAP:
                        return
                    budget["calls"] += 1
                body = "\n\n".join(fmt_finding(f, repo_dir) for f in fbatches[fi_])
                try:
                    user = USER_TMPL.format(lang="TypeScript/JavaScript", items=body)
                    text, rj = _call_local(SYSTEM + "\n\n" + user, len(fbatches[fi_]))
                    with lock:
                        budget["in_tok"] += rj.get("tokens_evaluated", 0)
                        budget["out_tok"] += rj.get("tokens_predicted", 0)
                        with raw_path.open("a") as fh:
                            fh.write(json.dumps({"arm": arm, "batch": f"fill{fi_}",
                                                 "model": MODEL,
                                                 "uids": [f["_uid"] for f in fbatches[fi_]],
                                                 "raw": text}, ensure_ascii=False) + "\n")
                except Exception as e:
                    with lock:
                        print(f"  [{arm}] fill {fi_} ERROR {str(e)[:120]}", flush=True)

            with ThreadPoolExecutor(max_workers=WORKERS) as ex:
                list(ex.map(fill, range(len(fbatches))))
            n_fill = len(fbatches)
            collect()

        out_findings = []
        cnt = {"TRUE": 0, "FALSE": 0, "UNCERTAIN": 0, "unjudged": 0}
        false_without_basis = 0
        for f in uniq:
            rec = {k: f[k] for k in ("file", "line", "category", "cwe", "source_file",
                                     "source_line", "sink", "source", "rule_pattern",
                                     "rule_field") if k in f}
            rec["dup_count"] = f["_dup_count"]
            rec["provenance"] = f.get("provenance", "graph")
            q = next((x for x in quarantined
                      if x["file"] == f["file"] and x["line"] == f.get("line")
                      and x["category"] == f["category"]), None)
            if q:
                rec["critic_verdict"] = "evidence_mismatch"
                rec["evidence_problems"] = q["problems"]
                cnt["unjudged"] += 1
            else:
                v = verdicts.get(f["_uid"])
                if v:
                    vd = v.get("verdict")
                    vd = vd if vd in ("TRUE", "FALSE", "UNCERTAIN") else "UNCERTAIN"
                    rec["critic_verdict"] = vd
                    rec["critic_confidence"] = v.get("confidence")
                    rec["critic_basis_line"] = v.get("basis_line")
                    rec["critic_reason"] = v.get("reason")
                    cnt[vd] += 1
                    if vd == "FALSE" and v.get("basis_line") is None:
                        false_without_basis += 1
                else:
                    rec["critic_verdict"] = "unjudged"
                    cnt["unjudged"] += 1
            out_findings.append(rec)

        n_files = d["n_files"]
        n_true = cnt["TRUE"]
        n_tu = cnt["TRUE"] + cnt["UNCERTAIN"]
        removed = cnt["FALSE"] / len(uniq) if uniq else 0.0
        warn = removed >= REMOVAL_WARN

        res = {
            "repo": repo, "arm": arm, "critic_model": MODEL,
            "temperature_setting": TEMPERATURE_SETTING,
            "temperature_api_error": TEMPERATURE_API_ERROR, "run_tag": RUNTAG,
            "n_files_scanned": n_files,
            "n_findings_pre_critic": dstat["n_findings_in"],
            "n_unique_locations": dstat["n_unique"],
            "evidence_validation": {
                "n_passed": len(sendable), "n_mismatch_quarantined": len(quarantined),
                "mismatch_examples": quarantined[:10],
                "rule": "§12-4-1 evidence 라인 == finding sink 라인",
            },
            "n_batches": len(batches), "n_fill_batches": n_fill,
            "n_batches_skipped": len(set(skipped)),
            "verdict_counts": cnt,
            "n_false_without_basis_line": false_without_basis,
            "scenario_TRUE_only": {
                "n_alerts": n_true,
                "alerts_per_file": round(n_true / n_files, 3) if n_files else 0.0,
                "n_files_with_alert": len({x["file"] for x in out_findings
                                           if x["critic_verdict"] == "TRUE"}),
            },
            "scenario_TRUE_plus_UNCERTAIN": {
                "n_alerts": n_tu,
                "alerts_per_file": round(n_tu / n_files, 3) if n_files else 0.0,
                "n_files_with_alert": len({x["file"] for x in out_findings
                                           if x["critic_verdict"] in ("TRUE", "UNCERTAIN")}),
            },
            "removal_rate_FALSE": round(removed, 4),
            "removal_warning_over_90pct": warn,
            "removal_warning_note": ("§12-4-5: critic 이 한 arm 의 90% 이상을 FALSE 로 지우면 "
                                     "정상이 아니다. 경고로 기록한다."),
            "unjudged_note": "unjudged / evidence_mismatch 는 TRUE 로 세지 않는다.",
            "findings": out_findings,
        }
        (OUT / f"graph_spec_critic_r3_{arm}_{repo}.json" if RUNTAG == "a" else OUT / f"graph_spec_critic_r3_{arm}_{repo}_run{RUNTAG}.json").write_text(
            json.dumps(res, ensure_ascii=False, indent=2))
        summary["arms"][arm] = {k: res[k] for k in
                                ("n_findings_pre_critic", "n_unique_locations",
                                 "verdict_counts", "scenario_TRUE_only",
                                 "scenario_TRUE_plus_UNCERTAIN", "removal_rate_FALSE",
                                 "removal_warning_over_90pct", "n_false_without_basis_line")}
        summary["arms"][arm]["evidence_mismatch"] = len(quarantined)
        print(json.dumps(summary["arms"][arm], ensure_ascii=False), flush=True)
        if warn:
            print(f"  ⚠ [{arm}] critic 이 {removed:.1%} 를 FALSE 로 제거 — §12-4-5 경고", flush=True)

    summary.update({"critic_calls_made": budget["calls"],
                    "input_tokens": budget["in_tok"], "output_tokens": budget["out_tok"],
                    "wall_clock_seconds": round(time.time() - t0, 1)})
    (OUT / f"graph_spec_critic_meta_r3_{RUNTAG}_{repo}.json").write_text(
        json.dumps(summary, ensure_ascii=False, indent=2))
    print(json.dumps({k: v for k, v in summary.items() if k != "arms"},
                     ensure_ascii=False, indent=2))


if __name__ == "__main__":
    OUT.mkdir(exist_ok=True)
    main(sys.argv[1], Path(sys.argv[2]), sys.argv[3:] or ["R2"])
