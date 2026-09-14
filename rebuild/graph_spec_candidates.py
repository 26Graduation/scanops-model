"""GRAPH-SPEC §5-1 — 후보 API 추출.

레포 전체를 CPG 하나로 올려 `joern/queries/dump_candidates.sc` 를 돌린다.
호출 이름 단위로 dedupe 하므로 **후보 수는 파일 수(257)와 무관**하다.
이것이 §5 "후보를 1건씩 호출하지 말 것"을 지킬 수 있는 전제다.

실행: python rebuild/graph_spec_candidates.py juice-shop /tmp/scanops_repobench/juice-shop
출력: rebuild/out/graph_spec_candidates_{repo}.json
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

from repo_bench_scan import scan_files  # noqa: E402

JOERN_BIN = str(REPO / ".joern_dist" / "joern-cli" / "joern")
SCRIPT = str(REPO / "joern" / "queries" / "dump_candidates.sc")
XMX = os.getenv("JOERN_XMX", "4g")
TIMEOUT = int(os.getenv("JOERN_TIMEOUT", "1800"))
# PLAN.md 0단계: 명시 안 된 레포는 JSSRC로 기본값 처리(지금 다루는 레포가 전부 JS/TS라
# CVEfixes F1 필터에서 이미 확인됨, GRAPH_RUN_SPEC.md §5). juice-shop 값은 그대로 둔다.
JLANG = {"juice-shop": "JSSRC"}


def stage(repo: str, repo_dir: Path, work: Path) -> tuple[Path, int]:
    """스캔 범위 파일을 상대경로 그대로 work/src 아래로 복사한다."""
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


def main(repo: str, repo_dir: Path) -> None:
    jl = JLANG.get(repo, "JSSRC")
    work = Path(os.getenv("TMPDIR", "/tmp")) / f"scanops_gspec_{repo}"
    src, n_files = stage(repo, repo_dir, work)
    out_file = work / "candidates.json"

    env = dict(os.environ)
    env["JAVA_OPTS"] = f"-Xmx{XMX}"
    env["_JAVA_OPTIONS"] = f"-Xmx{XMX}"
    cmd = [JOERN_BIN, "--script", SCRIPT,
           "--param", f"inDir={src}", "--param", f"lang={jl}",
           "--param", f"outFile={out_file}"]
    print(f"[cand] files={n_files} xmx={XMX}", flush=True)
    t0 = time.time()
    p = subprocess.run(cmd, env=env, cwd=str(work), capture_output=True,
                       text=True, timeout=TIMEOUT)
    el = round(time.time() - t0, 1)
    if not out_file.exists():
        print(p.stdout[-3000:]); print(p.stderr[-3000:])
        raise SystemExit(f"dump 실패 rc={p.returncode}")
    d = json.loads(out_file.read_text())
    d.update({"repo": repo, "n_files": n_files, "elapsed_seconds": el,
              "joern_returncode": p.returncode, "staged_dir": str(src),
              "commit": subprocess.run(["git", "-C", str(repo_dir), "rev-parse", "HEAD"],
                                       capture_output=True, text=True).stdout.strip()})
    dst = OUT / f"graph_spec_candidates_{repo}.json"
    dst.write_text(json.dumps(d, ensure_ascii=False, indent=2))
    print(json.dumps({k: d[k] for k in ("n_calls_total", "n_call_candidates",
                                        "n_param_candidates", "elapsed_seconds")},
                     ensure_ascii=False, indent=2))
    print(f"저장: {dst}")


if __name__ == "__main__":
    OUT.mkdir(exist_ok=True)
    main(sys.argv[1], Path(sys.argv[2]))
