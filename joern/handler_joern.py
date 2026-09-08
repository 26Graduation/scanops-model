"""ScanOps Joern 워커 — 서버리스(RunPod) · 온프레미스(HTTP) · 배치(CLI) 공용

세 진입점이 같은 엔진(`analyze_batch`)을 쓴다:
  1) RunPod serverless : `handler(job)`            — SaaS 경로
  2) 온프레미스 HTTP   : `uvicorn joern.handler_joern:app`  — 외부 호출 0
  3) 벤치 배치 CLI     : `python -m joern.handler_joern --batch manifest.json`

설계 근거는 JOERN_HYBRID_REPORT.md §2 참조. 요약:
  - 요청마다 /tmp/scanops_{job_id}/ 를 새로 만들고 그 안에만 쓴다. job_id 중복 거부.
    종료(성공·실패·타임아웃 전부) 시 rm -rf 하고 삭제 로그를 남긴다.
  - Joern은 확장자로 언어를 고른다 → 쓸 때 언어별 확장자를 강제로 붙인다(joern/langmap.py).
  - CleanVul은 함수 조각이라 클래스/import 껍데기가 없다 → 1차 원문, 2차 최소 껍데기 래핑
    재시도(wrap_level 0|1).
  - 배치는 케이스마다 JVM을 띄우지 않는다. 청크(기본 25건)당 CPG 1개를 만들고 청크가 끝나면
    close+delete 한다. 청크마다 RSS를 기록해 단조 증가하면 JVM을 재기동한다.
"""
from __future__ import annotations

import json
import os
import re
import shutil
import subprocess
import sys
import threading
import time
from pathlib import Path
from typing import Any, Iterable

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from joern.langmap import ensure_ext, resolve  # noqa: E402

JOERN_BIN = os.getenv("JOERN_BIN", "joern")
# sanitizer 표(sanFile)를 받는 쿼리 버전. v3 이상은 전부 지원한다.
# (실측 사고: "taint_v3" 문자열 비교로 두었더니 taint_v4 에 sanFile 이 안 넘어가
#  sanitizer 가 통째로 죽었다 — 스모크에서 safe_sanitized 가 0건이 되어 발견.)
_SAN_AWARE_RE = re.compile(r"taint_v(\d+)\.sc$")

SCRIPT = os.getenv("JOERN_SCRIPT", str(Path(__file__).resolve().parent / "queries" / "taint.sc"))
WORK_ROOT = Path(os.getenv("JOERN_WORK_ROOT", "/tmp"))
CHUNK_SIZE = int(os.getenv("JOERN_CHUNK", "25"))
CASE_TIMEOUT = int(os.getenv("JOERN_CASE_TIMEOUT", "90"))       # 케이스당 상한(초)
XMX = os.getenv("JOERN_XMX", "4g")
RSS_GROWTH_LIMIT_MB = int(os.getenv("JOERN_RSS_LIMIT_MB", "6000"))

_ACTIVE_JOBS: set[str] = set()
_ACTIVE_LOCK = threading.Lock()

_SAFE = re.compile(r"[^A-Za-z0-9_.-]")


# ── 유틸 ────────────────────────────────────────────────────────────────────

def _log(msg: str) -> None:
    print(f"[joern] {msg}", flush=True)


def _safe_stem(case_id: str, taken: set[str]) -> str:
    """case_id → 파일명 안전 stem. 충돌 시 접미사. 역변환은 호출측이 표로 보관."""
    s = _SAFE.sub("_", case_id).strip("._") or "case"
    s = s[:120]
    base, i = s, 1
    while s in taken:
        s = f"{base}~{i}"
        i += 1
    taken.add(s)
    return s


def _wrap(code: str, joern_lang: str) -> str:
    """2차 시도용 최소 껍데기. 파싱만 통과하면 되므로 최소한으로."""
    if joern_lang == "JAVASRC":
        if re.search(r"\b(class|interface|enum|record)\s+\w", code):
            return code
        return "public class ScanopsSnippet {\n" + code + "\n}\n"
    if joern_lang == "JSSRC":
        # 최상위 return/await 등을 감싸 파싱 통과
        return "function __scanops_wrap__() {\n" + code + "\n}\n"
    if joern_lang == "PYTHONSRC":
        # 파이썬은 들여쓰기 때문에 감싸면 오히려 깨진다 → 좌측 정렬만 시도
        lines = [l for l in code.splitlines() if l.strip()]
        if not lines:
            return code
        indent = min(len(l) - len(l.lstrip()) for l in lines)
        if indent == 0:
            return code
        return "\n".join(l[indent:] if len(l) >= indent else l for l in code.splitlines())
    return code


def _peak_rss_mb(proc: subprocess.Popen, stop: threading.Event, out: dict) -> None:
    """프로세스 **트리** RSS 폴링.

    joern 실행 파일은 얇은 셸 래퍼이고 실제 메모리는 자식 JVM 이 쓴다. 래퍼 하나만 재면
    항상 1~2 MB 가 나와 OOM 판단이 불가능하다 → 후손 전체를 합산한다.
    """
    peak = 0
    while not stop.is_set():
        try:
            r = subprocess.run(["ps", "-eo", "pid=,ppid=,rss="],
                               capture_output=True, text=True, timeout=10)
            kids: dict[int, list[int]] = {}
            rss: dict[int, int] = {}
            for line in r.stdout.splitlines():
                parts = line.split()
                if len(parts) < 3:
                    continue
                pid, ppid, kb = int(parts[0]), int(parts[1]), int(parts[2])
                kids.setdefault(ppid, []).append(pid)
                rss[pid] = kb
            total, stack = 0, [proc.pid]
            seen: set[int] = set()
            while stack:
                p = stack.pop()
                if p in seen:
                    continue
                seen.add(p)
                total += rss.get(p, 0)
                stack.extend(kids.get(p, []))
            peak = max(peak, total // 1024)
        except Exception:  # noqa: BLE001
            pass
        stop.wait(2.0)
    out["peak_rss_mb"] = peak


# ── Joern 1회 실행 (청크 = CPG 1개) ─────────────────────────────────────────

def _run_chunk(in_dir: Path, joern_lang: str, out_file: Path, timeout: int) -> dict:
    env = dict(os.environ)
    env["JAVA_OPTS"] = f"-Xmx{XMX} {env.get('JAVA_OPTS', '')}".strip()
    env["_JAVA_OPTIONS"] = f"-Xmx{XMX}"
    cmd = [JOERN_BIN, "--script", SCRIPT,
           "--param", f"inDir={in_dir}",
           "--param", f"lang={joern_lang}",
           "--param", f"outFile={out_file}"]
    # v3(sanitizer-aware) 쿼리에만 있는 파라미터. v2 이하 스크립트에는 넘기지 않는다
    # (Joern 은 미정의 --param 을 오류로 취급한다).
    san_file = os.getenv("JOERN_SANITIZER_FILE", "")
    if san_file and _SAN_AWARE_RE.search(os.path.basename(SCRIPT)):
        cmd += ["--param", f"sanFile={san_file}"]
    # Joern 은 **CWD 아래에 `workspace/` 를 만든다**(실측). 레포 CWD 에서 돌리면
    # 프로젝트가 누적되고 요청끼리 충돌한다 → 청크 디렉토리의 부모(=job 전용 디렉토리)를
    # CWD 로 준다. job 종료 시 rm -rf 되므로 workspace 도 함께 사라진다.
    cwd = str(in_dir.parent)
    _log(f"RUN (cwd={cwd}) {' '.join(cmd)}")
    t0 = time.time()
    proc = subprocess.Popen(cmd, env=env, cwd=cwd, stdout=subprocess.PIPE,
                            stderr=subprocess.STDOUT, text=True)
    rss: dict = {"peak_rss_mb": 0}
    stop = threading.Event()
    th = threading.Thread(target=_peak_rss_mb, args=(proc, stop, rss), daemon=True)
    th.start()
    timed_out = False
    try:
        stdout, _ = proc.communicate(timeout=timeout)
    except subprocess.TimeoutExpired:
        timed_out = True
        proc.kill()
        stdout, _ = proc.communicate()
    finally:
        stop.set()
        th.join(timeout=5)
    elapsed = round(time.time() - t0, 2)
    data: dict = {}
    if out_file.exists():
        try:
            data = json.loads(out_file.read_text() or "{}")
        except Exception as e:  # noqa: BLE001
            data = {"error": f"bad_json: {e}"}
    return {"data": data, "elapsed": elapsed, "timed_out": timed_out,
            "rc": proc.returncode, "peak_rss_mb": rss.get("peak_rss_mb", 0),
            "stdout_tail": (stdout or "")[-2000:]}


# ── 엔진 ────────────────────────────────────────────────────────────────────

def analyze_batch(job_id: str, language: str, files: list[dict],
                  chunk_size: int | None = None) -> dict:
    """files = [{"path": <case_id 또는 파일경로>, "content": <코드>}, ...]

    반환: {"job_id", "results": {case_id: {...}}, "unknown_reason", "elapsed", "rss_curve"}
    결과 건수는 항상 입력 건수와 같다 (누락은 unknown 으로 채움).
    """
    t_all = time.time()
    resolved = resolve(language)
    if resolved is None:
        return {"job_id": job_id, "language": language, "results": {
            f["path"]: {"verdict": "unknown", "unknown_reason": "unsupported_lang",
                        "categories": [], "findings": [], "wrap_level": None,
                        "elapsed": 0.0} for f in files},
            "unknown_reason": "unsupported_lang", "elapsed": 0.0, "rss_curve": []}
    ext, joern_lang = resolved

    with _ACTIVE_LOCK:
        if job_id in _ACTIVE_JOBS:
            raise ValueError(f"duplicate job_id: {job_id}")
        _ACTIVE_JOBS.add(job_id)

    root = WORK_ROOT / f"scanops_{_SAFE.sub('_', job_id)}"
    if root.exists():
        raise ValueError(f"work dir already exists (duplicate job_id): {root}")
    root.mkdir(parents=True)

    results: dict[str, dict] = {}
    id_map: dict[str, str] = {}      # stem -> case_id (역변환 표)
    rss_curve: list[dict] = []
    try:
        pending = [(f["path"], f.get("content", "")) for f in files]
        for wrap_level in (0, 1):
            if not pending:
                break
            done, still = _pass(root, pending, ext, joern_lang, wrap_level,
                                chunk_size or CHUNK_SIZE, id_map, rss_curve)
            results.update(done)
            pending = still
        # 두 시도 모두 실패 → parse_fail
        for cid, _code in pending:
            results[cid] = {"verdict": "unknown", "unknown_reason": "parse_fail",
                            "categories": [], "findings": [], "wrap_level": 1,
                            "elapsed": 0.0}
    finally:
        shutil.rmtree(root, ignore_errors=True)
        _log(f"CLEANUP rm -rf {root} exists_after={root.exists()}")
        with _ACTIVE_LOCK:
            _ACTIVE_JOBS.discard(job_id)

    # 건수 보존 확인
    for f in files:
        results.setdefault(f["path"], {
            "verdict": "unknown", "unknown_reason": "id_unmapped",
            "categories": [], "findings": [], "wrap_level": None, "elapsed": 0.0})

    return {"job_id": job_id, "language": language, "joern_lang": joern_lang,
            "results": results, "unknown_reason": None,
            "elapsed": round(time.time() - t_all, 2), "rss_curve": rss_curve,
            "id_map": id_map}


def _pass(root: Path, cases: list[tuple[str, str]], ext: str, joern_lang: str,
          wrap_level: int, chunk_size: int, id_map: dict[str, str],
          rss_curve: list[dict]) -> tuple[dict[str, dict], list[tuple[str, str]]]:
    """한 패스(wrap_level 고정)를 청크 단위로 실행. (성공분, 실패분) 반환."""
    ok: dict[str, dict] = {}
    failed: list[tuple[str, str]] = []
    for ci in range(0, len(cases), chunk_size):
        chunk = cases[ci:ci + chunk_size]
        cdir = root / f"w{wrap_level}_c{ci // chunk_size}"
        cdir.mkdir(parents=True, exist_ok=True)
        taken: set[str] = set()
        local: dict[str, str] = {}   # filename -> case_id
        for cid, code in chunk:
            stem = _safe_stem(cid, taken)
            fname = ensure_ext(stem, ext)
            body = _wrap(code, joern_lang) if wrap_level == 1 else code
            (cdir / fname).write_text(body, errors="replace")
            local[fname] = cid
            id_map[fname] = cid
        out_file = cdir.with_suffix(".json")
        timeout = CASE_TIMEOUT * len(chunk)
        r = _run_chunk(cdir, joern_lang, out_file, timeout)
        rss_curve.append({"chunk": cdir.name, "n": len(chunk),
                          "peak_rss_mb": r["peak_rss_mb"], "elapsed": r["elapsed"],
                          "timed_out": r["timed_out"], "rc": r["rc"]})
        data = r["data"] or {}
        if r["timed_out"]:
            for fname, cid in local.items():
                ok[cid] = {"verdict": "unknown", "unknown_reason": "timeout",
                           "categories": [], "findings": [], "wrap_level": wrap_level,
                           "elapsed": r["elapsed"]}
            continue
        if data.get("error"):
            _log(f"CHUNK_IMPORT_FAIL {cdir.name}: {str(data.get('message'))[:200]} "
                 f"| tail={r['stdout_tail'][-400:]}")
            failed.extend(chunk)
            continue
        parsed = set(data.get("parsed") or [])
        by_file: dict[str, list] = {}
        for f in data.get("findings") or []:
            by_file.setdefault(f.get("file", ""), []).append(f)
        for fname, cid in local.items():
            if fname not in parsed and fname not in by_file:
                failed.append((cid, _code_of(chunk, cid)))
                continue
            fs = by_file.get(fname, [])
            # v3: sanitizer 에 걸린 flow 는 제외한다. 살아남은 flow 가 하나도 없고
            # 제외된 flow 가 있으면 safe 가 아니라 safe_sanitized 로 구분한다.
            # v2 이하 findings 에는 "sanitized" 키가 없어 전부 live 로 취급된다(하위호환).
            live = [x for x in fs if not x.get("sanitized")]
            blocked = [x for x in fs if x.get("sanitized")]
            if live:
                verdict = "vuln"
            elif blocked:
                verdict = "safe_sanitized"
            else:
                verdict = "safe"
            ok[cid] = {
                "verdict": verdict,
                "unknown_reason": None,
                "categories": sorted({x["category"] for x in live}),
                "sanitized_categories": sorted({x["category"] for x in blocked}),
                "sanitizer_hits": [h for x in blocked for h in (x.get("sanitizer_hits") or [])][:12],
                "findings": fs,
                "wrap_level": wrap_level,
                "elapsed": round(r["elapsed"] / max(1, len(chunk)), 3),
            }
    return ok, failed


def _code_of(chunk: list[tuple[str, str]], cid: str) -> str:
    for c, code in chunk:
        if c == cid:
            return code
    return ""


# ── 엔진 2: 레포 전체를 CPG 1개로 (2026-08-23, 베타 배포) ────────────────────
# analyze_batch/_pass 는 서로 독립된 벤치 케이스를 25건씩 쪼개 CPG를 여러 개 만든다
# (케이스 간 cross-file 참조가 없다는 전제). 실제 서비스의 레포 스캔은 그 반대 —
# 파일 사이 taint 흐름을 봐야 하므로 레포 전체를 한 CPG로 만들어야 한다
# (CLAUDE.md: "그래프 입력 단위: 함수 조각 → 레포 전체"). 기존 엔진은 건드리지
# 않고(연구/벤치 스크립트가 계속 씀) 완전히 별도 함수로 추가한다.

CANDIDATES_SCRIPT = os.getenv(
    "JOERN_CANDIDATES_SCRIPT", str(Path(__file__).resolve().parent / "queries" / "dump_candidates.sc"))
CANDIDATES_V2_SCRIPT = os.getenv(
    "JOERN_CANDIDATES_V2_SCRIPT",
    str(Path(__file__).resolve().parent / "queries" / "dump_candidates_v2.sc"))
TAINT_SPEC_SCRIPT = os.getenv(
    "JOERN_TAINT_SPEC_SCRIPT", str(Path(__file__).resolve().parent / "queries" / "taint_spec.sc"))
REPO_TIMEOUT = int(os.getenv("JOERN_REPO_TIMEOUT", "600"))


def run_repo_script(job_id: str, mode: str, language: str, files: list[dict],
                     spec_text: str = "", san_file: str = "", san_text: str = "",
                     prop_file: str = "", prop_text: str = "",
                     candidate_schema: str = "v1",
                     src_mode: str = "params", arm: str = "S2C",
                     timeout: int | None = None) -> dict:
    """레포 파일 전체를 한 디렉터리에 써서 Joern을 **한 번만** 돌린다.

    mode="candidates" → dump_candidates.sc (룰 생성 대상 후보 추출)
    mode="taint"       → taint_spec.sc (LLM이 만든 spec_text로 taint 쿼리, line 단위 findings)
    """
    if mode not in ("candidates", "taint"):
        return {"error": f"unknown mode: {mode}"}
    resolved = resolve(language)
    if resolved is None:
        return {"error": f"unsupported_lang: {language}"}
    _ext, joern_lang = resolved

    with _ACTIVE_LOCK:
        if job_id in _ACTIVE_JOBS:
            raise ValueError(f"duplicate job_id: {job_id}")
        _ACTIVE_JOBS.add(job_id)
    root = WORK_ROOT / f"scanops_repo_{_SAFE.sub('_', job_id)}"
    if root.exists():
        raise ValueError(f"work dir already exists (duplicate job_id): {root}")
    in_dir = root / "repo"
    in_dir.mkdir(parents=True)
    out_file = root / "out.json"

    try:
        n_written = 0
        for f in files:
            rel = (f.get("path") or "").lstrip("/") or f"file{n_written}"
            # 경로 이탈(../) 방지 — 서비스 입력이라 방어적으로 처리
            dest = (in_dir / rel).resolve()
            if not str(dest).startswith(str(in_dir.resolve())):
                continue
            dest.parent.mkdir(parents=True, exist_ok=True)
            dest.write_text(f.get("content", ""), errors="replace")
            n_written += 1

        env = dict(os.environ)
        env["JAVA_OPTS"] = f"-Xmx{XMX} {env.get('JAVA_OPTS', '')}".strip()
        env["_JAVA_OPTIONS"] = f"-Xmx{XMX}"

        if mode == "candidates":
            candidate_script = CANDIDATES_V2_SCRIPT if candidate_schema == "v2" else CANDIDATES_SCRIPT
            cmd = [JOERN_BIN, "--script", candidate_script,
                   "--param", f"inDir={in_dir}", "--param", f"lang={joern_lang}",
                   "--param", f"outFile={out_file}"]
        else:  # taint
            spec_path = root / "spec.tsv"
            spec_path.write_text(spec_text, errors="replace")
            cmd = [JOERN_BIN, "--script", TAINT_SPEC_SCRIPT,
                   "--param", f"inDir={in_dir}", "--param", f"lang={joern_lang}",
                   "--param", f"outFile={out_file}", "--param", f"specFile={spec_path}",
                   "--param", f"arm={arm}", "--param", f"srcMode={src_mode}"]
            effective_san_file = san_file
            if san_text:
                san_path = root / "sanitizers.tsv"
                san_path.write_text(san_text, errors="replace")
                effective_san_file = str(san_path)
            if effective_san_file:
                cmd += ["--param", f"sanFile={effective_san_file}"]
            effective_prop_file = prop_file
            if prop_text:
                prop_path = root / "propagation.tsv"
                prop_path.write_text(prop_text, errors="replace")
                effective_prop_file = str(prop_path)
            if effective_prop_file:
                cmd += ["--param", f"propFile={effective_prop_file}"]

        _log(f"RUN_REPO mode={mode} lang={joern_lang} n_files={n_written} cmd={' '.join(cmd)}")
        t0 = time.time()
        cid_file = root / "joern-container.cid"
        env["JOERN_CIDFILE"] = str(cid_file)
        proc = subprocess.Popen(cmd, env=env, cwd=str(root), stdout=subprocess.PIPE,
                                stderr=subprocess.STDOUT, text=True)
        rss: dict = {"peak_rss_mb": 0}
        stop = threading.Event()
        th = threading.Thread(target=_peak_rss_mb, args=(proc, stop, rss), daemon=True)
        th.start()
        timed_out = False
        try:
            stdout, _ = proc.communicate(timeout=timeout or REPO_TIMEOUT)
        except subprocess.TimeoutExpired:
            timed_out = True
            proc.kill()
            # Killing `docker run` only kills the client.  Without removing the
            # container, Joern keeps consuming CPU/RAM and `communicate()` may
            # wait indefinitely because descendants retain the output pipe.
            if cid_file.exists():
                cid = cid_file.read_text(errors="replace").strip()
                if cid:
                    try:
                        subprocess.run(["docker", "rm", "-f", cid],
                                       stdout=subprocess.DEVNULL,
                                       stderr=subprocess.DEVNULL, timeout=30)
                    except Exception as cleanup_error:  # noqa: BLE001
                        _log(f"container timeout cleanup failed cid={cid}: {cleanup_error}")
            try:
                stdout, _ = proc.communicate(timeout=30)
            except subprocess.TimeoutExpired:
                stdout = ""
        finally:
            stop.set()
            th.join(timeout=5)
        elapsed = round(time.time() - t0, 2)
        data: dict = {}
        if out_file.exists():
            try:
                data = json.loads(out_file.read_text() or "{}")
            except Exception as e:  # noqa: BLE001
                data = {"error": f"bad_json: {e}"}
        if timed_out:
            data = {"error": "timeout"}
        return {"mode": mode, "n_files": n_written, "data": data, "elapsed": elapsed,
                "timed_out": timed_out, "rc": proc.returncode,
                "peak_rss_mb": rss.get("peak_rss_mb", 0),
                "stdout_tail": (stdout or "")[-2000:]}
    finally:
        shutil.rmtree(root, ignore_errors=True)
        _log(f"CLEANUP rm -rf {root} exists_after={root.exists()}")
        with _ACTIVE_LOCK:
            _ACTIVE_JOBS.discard(job_id)


# ── 진입점 1: RunPod serverless ─────────────────────────────────────────────

def handler(job: dict) -> dict:
    inp = job.get("input") or {}
    job_id = str(inp.get("job_id") or job.get("id") or f"j{int(time.time()*1000)}")
    language = inp.get("language") or ""
    files = inp.get("files") or []
    if not files:
        return {"error": "files required"}

    mode = inp.get("mode")
    if mode in ("candidates", "taint"):
        try:
            return run_repo_script(
                job_id, mode, language, files,
                spec_text=inp.get("spec_text", ""),
                san_file=inp.get("san_file", ""),
                san_text=inp.get("san_text", ""),
                prop_file=inp.get("prop_file", ""),
                prop_text=inp.get("prop_text", ""),
                candidate_schema=inp.get("candidate_schema", "v1"),
                src_mode=inp.get("src_mode", "params"),
                arm=inp.get("arm", "S2C"),
                timeout=inp.get("timeout"),
            )
        except ValueError as e:
            return {"error": str(e)}
        except Exception as e:  # noqa: BLE001
            return {"error": f"joern worker error: {e}"}

    try:
        r = analyze_batch(job_id, language, files)
    except ValueError as e:
        return {"error": str(e)}
    except Exception as e:  # noqa: BLE001
        return {"error": f"joern worker error: {e}"}
    # 단건 호출 형태로도 읽히게 findings 평탄화 제공
    flat = []
    for cid, v in r["results"].items():
        for f in v["findings"]:
            flat.append({**f, "file": cid})
    return {"job_id": r["job_id"], "results": r["results"], "findings": flat,
            "elapsed": r["elapsed"], "rss_curve": r["rss_curve"]}


# ── 진입점 2: 온프레미스 HTTP (FastAPI) ─────────────────────────────────────

try:  # 요청 모델은 **모듈 레벨**이어야 한다.
    from pydantic import BaseModel

    class FileIn(BaseModel):
        path: str
        content: str

    class JoernRequest(BaseModel):
        job_id: str
        language: str
        files: list[FileIn]

    class JoernRepoRequest(BaseModel):
        job_id: str
        mode: str
        language: str
        files: list[FileIn]
        spec_text: str = ""
        san_file: str = ""
        san_text: str = ""
        prop_file: str = ""
        prop_text: str = ""
        candidate_schema: str = "v1"
        src_mode: str = "params"
        arm: str = "S2C"
except ImportError:  # pydantic 없이 CLI/RunPod 로만 쓸 때
    FileIn = JoernRequest = JoernRepoRequest = None  # type: ignore[assignment,misc]


def _build_app():
    # 이 파일은 `from __future__ import annotations` 를 쓴다 → 어노테이션이 전부 문자열이 되고
    # FastAPI 는 그것을 **모듈 전역**에서 해석한다. 모델을 이 함수 안에 두면 이름을 찾지 못해
    # 본문 파라미터가 쿼리 파라미터로 오인되고 422 가 난다 (실측 후 교정).
    from fastapi import FastAPI, HTTPException

    api = FastAPI(title="ScanOps Joern Worker", version="joern-1")
    _store: dict[str, dict] = {}

    @api.get("/health")
    def health():
        return {"status": "ok", "joern_bin": JOERN_BIN, "xmx": XMX}

    @api.post("/joern/submit")
    def submit(req: JoernRequest):
        if req.job_id in _store:
            raise HTTPException(409, "duplicate job_id")
        _store[req.job_id] = {"status": "RUNNING"}

        def _work():
            try:
                _store[req.job_id] = {"status": "DONE", "result": analyze_batch(
                    req.job_id, req.language,
                    [{"path": f.path, "content": f.content} for f in req.files])}
            except Exception as e:  # noqa: BLE001
                _store[req.job_id] = {"status": "FAILED", "error": str(e)}

        threading.Thread(target=_work, daemon=True).start()
        return {"job_id": req.job_id, "status": "RUNNING"}

    @api.get("/joern/result/{job_id}")
    def result(job_id: str):
        if job_id not in _store:
            raise HTTPException(404, "unknown job_id")
        return _store[job_id]

    @api.post("/joern/analyze")
    def analyze_sync(req: JoernRequest):
        return analyze_batch(req.job_id, req.language,
                             [{"path": f.path, "content": f.content} for f in req.files])

    @api.post("/joern/repo")
    def repo_sync(req: JoernRepoRequest):
        """레포단위(§24, 2026-08-23) — RunPod 서버리스 워커 디스패치 문제로 온프레미스
        HTTP 모드(항상 켜진 Pod)를 대신 쓴다. 동기 호출, 클라이언트가 넉넉한 타임아웃을 준다."""
        try:
            return run_repo_script(
                req.job_id, req.mode, req.language,
                [{"path": f.path, "content": f.content} for f in req.files],
                spec_text=req.spec_text, san_file=req.san_file, san_text=req.san_text,
                prop_file=req.prop_file, prop_text=req.prop_text,
                candidate_schema=req.candidate_schema,
                src_mode=req.src_mode, arm=req.arm)
        except ValueError as e:
            raise HTTPException(409, str(e))

    return api


app = None
if os.getenv("JOERN_HTTP", "").lower() not in ("", "0", "off", "false"):
    app = _build_app()


# ── 진입점 3: 배치 CLI ──────────────────────────────────────────────────────

def _main(argv: list[str]) -> int:
    import argparse
    p = argparse.ArgumentParser()
    p.add_argument("--batch", required=True, help="manifest json: {job_id,language,files:[...]}")
    p.add_argument("--out", required=True)
    p.add_argument("--chunk", type=int, default=CHUNK_SIZE)
    a = p.parse_args(argv)
    m = json.loads(Path(a.batch).read_text())
    r = analyze_batch(m["job_id"], m["language"], m["files"], chunk_size=a.chunk)
    Path(a.out).write_text(json.dumps(r, ensure_ascii=False))
    _log(f"WROTE {a.out} n={len(r['results'])}")
    return 0


if __name__ == "__main__":
    if os.getenv("RUNPOD_MODE", "").lower() in ("1", "on", "true"):
        import runpod
        runpod.serverless.start({"handler": handler})
    else:
        raise SystemExit(_main(sys.argv[1:]))
