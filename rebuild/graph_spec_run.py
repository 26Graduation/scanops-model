"""GRAPH-SPEC §4/§5-4 — arm 별 Joern 실행.

  S2-A : 손 룰(taint_v4.sc JSSRC) + 손 sanitizer(sanitizers.json)
  S2-B : LLM 스펙만 + LLM sanitizer + LLM 오염전파
  S2-C : §4-1 합집합 (룰 합집합, sanitizer 합집합, 전파 규칙 유지)

S1 은 LLM 단독이라 그래프를 돌리지 않는다 — 기존 측정(repo_bench_juice-shop_s1.jsonl)을 쓴다.

실행: python rebuild/graph_spec_run.py juice-shop /tmp/scanops_repobench/juice-shop S2A S2B S2C
출력: rebuild/out/graph_spec_arm_{arm}_{repo}.json   (arm 별 raw, 각각 별도 파일)
"""
from __future__ import annotations

import json
import os
import shutil
import subprocess
import sys
import time
from pathlib import Path

ROOT = Path(__file__).resolve().parent
REPO = ROOT.parent
OUT = ROOT / "out"
sys.path.insert(0, str(REPO))
sys.path.insert(0, str(ROOT))

from joern.sanitizer_spec import write_san_file  # noqa: E402
from repo_bench_scan import scan_files  # noqa: E402

JOERN_BIN = str(REPO / ".joern_dist" / "joern-cli" / "joern")
SCRIPT = str(REPO / "joern" / "queries" / "taint_spec.sc")
XMX = os.getenv("JOERN_XMX", "4g")
TIMEOUT = int(os.getenv("JOERN_TIMEOUT", "2400"))
# PLAN.md 0단계: 명시 안 된 레포는 JSSRC 기본값(지금 다루는 레포가 전부 JS/TS). juice-shop 값은 그대로.
JLANG = {"juice-shop": "JSSRC"}


def stage(repo: str, repo_dir: Path, work: Path) -> tuple[Path, int]:
    if work.exists():
        shutil.rmtree(work)
    src = work / "src"
    src.mkdir(parents=True)
    files = scan_files(repo, repo_dir)
    for rel, code in files:
        dst = src / rel
        dst.parent.mkdir(parents=True, exist_ok=True)
        dst.write_text(code, encoding="utf-8")
    return src, len(files)


def san_for_arm(repo: str, arm: str, jl: str, work: Path) -> tuple[Path, int]:
    """arm 별 sanFile. S2-A=손, S2-B=LLM, S2-C=합집합."""
    hand = work / "_san_hand.txt"
    n_hand = write_san_file(jl, hand)
    llm_p = OUT / f"san_S2B_{repo}.tsv"
    llm_txt = llm_p.read_text() if llm_p.exists() else ""
    n_llm = len([x for x in llm_txt.splitlines() if x.strip()])
    dest = work / f"_san_{arm}.txt"
    if arm == "S2A":
        dest.write_text(hand.read_text())
        return dest, n_hand
    if arm == "S2B":
        dest.write_text(llm_txt)
        return dest, n_llm
    dest.write_text(hand.read_text().rstrip("\n") + "\n" + llm_txt)
    return dest, n_hand + n_llm


def run_arm(repo: str, arm: str, src: Path, work: Path, jl: str, n_files: int) -> dict:
    spec = OUT / f"spec_{arm}_{repo}.tsv"
    prop = OUT / f"prop_{arm}_{repo}.tsv"
    san, n_san = san_for_arm(repo, arm, jl, work)
    out_file = work / f"result_{arm}.json"

    env = dict(os.environ)
    env["JAVA_OPTS"] = f"-Xmx{XMX}"
    env["_JAVA_OPTIONS"] = f"-Xmx{XMX}"
    cmd = [JOERN_BIN, "--script", SCRIPT,
           "--param", f"inDir={src}", "--param", f"lang={jl}",
           "--param", f"outFile={out_file}", "--param", f"specFile={spec}",
           "--param", f"sanFile={san}", "--param", f"arm={arm}",
           # 2라운드 STEP 5: GSPEC_SRC_MODE=r2 면 파라미터뿌리 fieldAccess 를 source 에 더한다.
           # 기본값은 params 라 1라운드 실행은 그대로 재현된다.
           "--param", f"srcMode={os.getenv('GSPEC_SRC_MODE', 'params')}"]
    if prop.exists() and prop.read_text().strip():
        cmd += ["--param", f"propFile={prop}"]
    print(f"[{arm}] 시작 (files={n_files}, sanitizers={n_san})", flush=True)
    t0 = time.time()
    timed_out = False
    try:
        p = subprocess.run(cmd, env=env, cwd=str(work), capture_output=True,
                           text=True, timeout=TIMEOUT)
        rc, tail = p.returncode, (p.stdout or "")[-4000:]
        err = (p.stderr or "")[-3000:]
    except subprocess.TimeoutExpired as e:
        timed_out, rc = True, -9
        tail = (e.stdout or b"").decode(errors="replace")[-4000:] if e.stdout else ""
        err = ""
    el = round(time.time() - t0, 1)

    payload = None
    if out_file.exists():
        try:
            payload = json.loads(out_file.read_text())
        except json.JSONDecodeError:
            payload = None

    res = {"repo": repo, "arm": arm, "joern_lang": jl, "xmx": XMX, "n_files": n_files,
           "spec_file": str(spec), "prop_file": str(prop) if prop.exists() else None,
           "n_sanitizer_patterns": n_san, "elapsed_seconds": el, "timed_out": timed_out,
           "returncode": rc, "result": payload, "stdout_tail": tail, "stderr_tail": err}
    if payload and "findings" in payload:
        fi = payload["findings"]
        unsan = [x for x in fi if not x.get("sanitized")]
        files_seen = payload.get("parsed") or []
        res.update({
            "n_findings": len(fi),
            "n_findings_unsanitized": len(unsan),
            "n_findings_sanitized": len(fi) - len(unsan),
            "n_files_parsed": len(files_seen),
            "n_files_with_alert": len({x["file"] for x in unsan}),
            "alerts_per_file": round(len(unsan) / n_files, 3),
        })
    dst = OUT / f"graph_spec_arm_{arm}_{repo}.json"
    dst.write_text(json.dumps(res, ensure_ascii=False, indent=2))
    print(json.dumps({k: res.get(k) for k in
                      ("arm", "n_findings", "n_findings_unsanitized", "n_files_with_alert",
                       "alerts_per_file", "elapsed_seconds", "timed_out", "returncode")},
                     ensure_ascii=False), flush=True)
    if payload is None:
        print(f"[{arm}] 결과 없음 — stdout tail:\n{tail[-1500:]}\nstderr:\n{err[-1500:]}", flush=True)
    return res


def main(repo: str, repo_dir: Path, arms: list[str]) -> None:
    jl = JLANG.get(repo, "JSSRC")
    work = Path(os.getenv("TMPDIR", "/tmp")) / f"scanops_gspec_run_{repo}"
    src, n_files = stage(repo, repo_dir, work)
    for arm in arms:
        run_arm(repo, arm, src, work, jl, n_files)


if __name__ == "__main__":
    OUT.mkdir(exist_ok=True)
    main(sys.argv[1], Path(sys.argv[2]), sys.argv[3:] or ["S2A", "S2B", "S2C"])
