"""Phase B — Joern **프로젝트 단위 CPG** (S2 의 세 번째 성분)

기존 벤치(`joern/bench_joern_v4.py`)는 "파일 하나 = 케이스 하나"를 25개씩 묶어
CPG 를 만든다. 여기서는 **레포 전체를 CPG 하나로** 올려 파일 간 흐름이 잡히는지 본다.

사양 §6-c 의 OOM/시간 폴백:
  - `-Xmx` 는 기본 4g (로컬에 llama-server 가 ~6GB 를 쓰고 있어 60% 규칙을 그대로 쓰면
    LLM 스캔이 죽는다 — 이 사실과 값을 기록한다)
  - 빌드 상한 20분/레포. 초과·실패 시 **부분 그래프** 폴백:
    라우터/엔드포인트 파일 + 그 import 폐쇄(깊이 2) 묶음별 CPG.

실행: python rebuild/repo_bench_joern.py juice-shop /tmp/scanops_repobench/juice-shop
출력: rebuild/out/repo_bench_{repo}_joern.json
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
from repo_bench_scan import SCOPE, scan_files  # noqa: E402

JOERN_BIN = str(REPO / ".joern_dist" / "joern-cli" / "joern")
SCRIPT = str(REPO / "joern" / "queries" / "taint_v4.sc")
XMX = os.getenv("JOERN_XMX", "4g")
TIMEOUT = int(os.getenv("JOERN_TIMEOUT", "1200"))   # 20분 (사양 §6-c)
JLANG = {"juice-shop": "JSSRC"}


def run(repo: str, repo_dir: Path) -> None:
    jl = JLANG[repo]
    work = Path(os.getenv("TMPDIR", "/tmp")) / f"scanops_joern_{repo}"
    if work.exists():
        shutil.rmtree(work)
    src = work / "src"
    src.mkdir(parents=True)

    files = scan_files(repo, repo_dir)
    for rel, code in files:
        dst = src / rel
        dst.parent.mkdir(parents=True, exist_ok=True)
        dst.write_text(code, encoding="utf-8")

    san = work / "_san.txt"
    n_san = write_san_file(jl, san)
    out_file = work / "result.json"

    env = dict(os.environ)
    env["JAVA_OPTS"] = f"-Xmx{XMX}"
    env["_JAVA_OPTIONS"] = f"-Xmx{XMX}"
    cmd = [JOERN_BIN, "--script", SCRIPT,
           "--param", f"inDir={src}",
           "--param", f"lang={jl}",
           "--param", f"outFile={out_file}",
           "--param", f"sanFile={san}"]
    print(f"[joern] xmx={XMX} timeout={TIMEOUT}s files={len(files)} sanitizers={n_san}")
    print("[joern] " + " ".join(cmd), flush=True)

    t0 = time.time()
    timed_out = False
    try:
        p = subprocess.run(cmd, env=env, cwd=str(work), capture_output=True,
                           text=True, timeout=TIMEOUT)
        rc, tail = p.returncode, (p.stdout or "")[-4000:]
    except subprocess.TimeoutExpired as e:
        timed_out, rc = True, -9
        tail = (e.stdout or b"").decode(errors="replace")[-4000:] if e.stdout else ""
    elapsed = round(time.time() - t0, 1)

    findings = None
    if out_file.exists():
        try:
            findings = json.loads(out_file.read_text())
        except json.JSONDecodeError:
            findings = None

    res = {
        "repo": repo, "joern_lang": jl, "xmx": XMX, "n_files": len(files),
        "elapsed_seconds": elapsed, "timed_out": timed_out, "returncode": rc,
        "mode": "project-cpg",
        "fallback_partial_graph": False, "n_partial_bundles": 0,
        "n_sanitizer_patterns": n_san,
        "findings": findings,
        "stdout_tail": tail,
    }
    if findings is None:
        res["note"] = ("프로젝트 단위 CPG 가 결과를 내지 못했다. "
                       "사양 §6-c 폴백(부분 그래프)은 아래 partial 단계에서 시도한다.")
    else:
        vuln_files = sorted({k for k, v in findings.items()
                             if isinstance(v, dict) and v.get("verdict") == "vuln"})
        res["vuln_files"] = vuln_files
        res["verdict_counts"] = {}
        for v in findings.values():
            if isinstance(v, dict):
                k = v.get("verdict", "?")
                res["verdict_counts"][k] = res["verdict_counts"].get(k, 0) + 1

    p_out = OUT / f"repo_bench_{repo}_joern.json"
    p_out.write_text(json.dumps(res, ensure_ascii=False, indent=2))
    print(json.dumps({k: v for k, v in res.items()
                      if k not in ("findings", "stdout_tail")},
                     ensure_ascii=False, indent=2))
    print(f"저장: {p_out}")


def normalize(repo: str, repo_dir: Path) -> None:
    """taint_v4.sc 출력의 파일 키는 **basename** 이다. 정답표는 상대경로다 → 매핑한다.

    basename 이 여러 파일에 겹치면 그 findings 는 **어느 파일인지 특정할 수 없다**.
    이 경우 겹치는 파일 전부를 vuln 으로 세면 Joern 에 유리해지고, 전부 버리면 불리해진다.
    → **두 값을 모두 기록**하고, 채점에는 관대한 쪽(전부 인정)을 쓴다. 표 각주에 적는다.
    """
    p = OUT / f"repo_bench_{repo}_joern.json"
    d = json.loads(p.read_text())
    raw = d.get("findings") or {}
    fi = raw.get("findings", []) if isinstance(raw, dict) else []

    files = [rel for rel, _ in scan_files(repo, repo_dir)]
    by_base: dict[str, list[str]] = {}
    for rel in files:
        by_base.setdefault(Path(rel).name, []).append(rel)

    unsan = [x for x in fi if not x.get("sanitized")]
    vuln_lenient: set[str] = set()
    vuln_strict: set[str] = set()
    unresolved: set[str] = set()
    ambiguous: dict[str, int] = {}
    for x in unsan:
        cands = by_base.get(x["file"], [])
        if not cands:
            unresolved.add(x["file"])
        elif len(cands) == 1:
            vuln_lenient.add(cands[0])
            vuln_strict.add(cands[0])
        else:
            vuln_lenient.update(cands)
            ambiguous[x["file"]] = len(cands)

    d["n_findings"] = len(fi)
    d["n_findings_unsanitized"] = len(unsan)
    d["n_findings_sanitized"] = len(fi) - len(unsan)
    d["vuln_files"] = sorted(vuln_lenient)
    d["vuln_files_strict"] = sorted(vuln_strict)
    d["basename_ambiguous"] = ambiguous
    d["basename_unresolved"] = sorted(unresolved)
    d["file_key_note"] = ("taint_v4.sc 는 basename 을 키로 낸다. 중복 basename 은 "
                          "관대(vuln_files)·엄격(vuln_files_strict) 두 값을 모두 남겼다. "
                          "채점에는 관대한 쪽을 썼다 = Joern 에 유리한 선택.")
    d["verdict_counts"] = {"vuln_files_lenient": len(vuln_lenient),
                           "vuln_files_strict": len(vuln_strict),
                           "files_parsed": len(raw.get("parsed", []))}
    p.write_text(json.dumps(d, ensure_ascii=False, indent=2))
    print(json.dumps({k: d[k] for k in
                      ("n_findings", "n_findings_unsanitized", "n_findings_sanitized",
                       "verdict_counts", "basename_ambiguous", "basename_unresolved",
                       "elapsed_seconds", "timed_out")}, ensure_ascii=False, indent=2))


if __name__ == "__main__":
    OUT.mkdir(exist_ok=True)
    if sys.argv[1] == "normalize":
        normalize(sys.argv[2], Path(sys.argv[3]))
    else:
        run(sys.argv[1], Path(sys.argv[2]))
