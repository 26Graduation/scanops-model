"""ScanOps v2 — 파일 단위 수확기 (V2_RUN_SPEC.md rev.6 §4·§5·§7·§8-2).

R4 파이프라인(`r4_cvefixes_harvest.py`/`_gitdiff.py`/`_linetruth.py`/`_filter.py`)을 재사용·확장한다.
새로 만드는 부분은 **파일 전문 추출**이다:

    git init
    git fetch --depth=2 <github주소> <fix commit hash>
    git show <hash>                     # diff 텍스트 — 삭제줄 정확한 위치 (R4 로직 그대로)
    git show <hash>~1:<path>            # 신규 — pre-fix 파일 전문 → 취약(label=vuln) 샘플
    git show <hash>:<path>              # 신규 — post-fix 파일 전문 → 안전(label=safe) 샘플

━━ 이번 라운드 필터 정책 (사용자 확정, 2026-08-21) ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
R4 의 F1~F7 중 **F1 과 F5 는 적용하지 않는다.** 근거를 남긴다:

  F1 (diff 에 JS/TS 파일이 있는가) — **제거**
      R4 의 F1 은 `EXT_JS` 하드 게이트(`r4_cvefixes_filter.py:119-121`)라 JS/TS 가 아닌 CVE 를
      통째로 버린다. 그런데 v2 는 §3/§5/§6 이 5개 언어를 요구한다. 실측하면 대상 2,651 CVE 중
      2,216건(83.6%)이 F1 에서 죽는다 → test cohort 641→435, train 풀 2,010→325 로 쪼그라들어
      §6 의 "300건 미만 → v2-lite" 폴백이 *데이터 부족*이 아니라 *필터 아티팩트*로 발동한다.
      그래서 언어 게이트를 없애고 5개 언어를 전부 수확한다.

  F5 (CWE 유형 ↔ 삭제줄 구문 부합) — **전 언어 미적용**
      `CWE_SYNTAX` 정규식이 Node/Express 어휘(`child_process`, `__dirname`, `require(`,
      `sequelize` …)로 짜여 있어 C/PHP/Python/Java 코드에 그대로 들이대면 정답 삭제줄이
      엉뚱하게 탈락한다 — 필터를 '확장'하는 게 아니라 '오작동'시키는 것이다. 언어별 키워드
      표를 새로 쓰는 건 스펙에 없는 새 규칙 설계라 §12 위반이고, 내가 키워드를 고르는 순간
      라벨 품질이 내 직관의 산물이 되어 §10-1 감사의 독립성이 깨진다. 그래서 전 언어에
      동일하게 미적용한다(5개 언어가 같은 강도의 필터만 받게 해서 §6 언어분포 표의 해석을
      오염시키지 않는다). 참고: C/C++ 는 R4 에서도 이미 90.6% 가 F5 미적용 상태였다.
      대가: 라벨 노이즈 상승 → PHASE 4 의 3분류 감사를 **언어별로** 기록해 근거로 쓴다(§7).

  F2 / F3 / F4 / F6 / F7 — **무수정 재사용.** 상수·정규식을 `r4_cvefixes_filter` 에서 import 한다.

파일의 `language` 는 **파일 확장자로 per-file 판정**한다(사용자 확정). v4_meta 의 CVE 단위
`language` 를 모든 파일에 붙이면 실측 4.7% 가 틀린 언어명으로 학습된다 — 프롬프트가
`Analyze the following {language} code` 라 모델이 그 글자를 그대로 읽기 때문이다.
5개 언어 확장자 맵에 없는 파일(.rb/.go/.rs — 6,111 중 17개)은 **제외하고 건수를 로그로 남긴다**
(CLAUDE.md 규칙 #10 "커버리지를 줄이는 결정을 조용히 하지 않는다").

출력: rebuild/data/v2_samples_raw.jsonl   (§7 스키마, vuln/safe 쌍)
      rebuild/out/v2_collect_report.json  (단계별 통과/탈락 집계)

실행:
  .venv/bin/python rebuild/collect_files_v2.py --cohort test --limit 100 --workers 10
  .venv/bin/python rebuild/collect_files_v2.py --cohort all --workers 10
"""
from __future__ import annotations

import argparse
import ast
import hashlib
import json
import os
import re
import shutil
import subprocess
import sys
import time
from collections import Counter, defaultdict
from concurrent.futures import ThreadPoolExecutor, as_completed
from pathlib import Path
from threading import Lock

ROOT = Path(__file__).resolve().parent
sys.path.insert(0, str(ROOT))

# R4 의 F3/F4/F6 상수를 그대로 가져온다 (재구현하지 않는다 — 숫자가 R4 와 비교 가능해야 한다).
from r4_cvefixes_filter import (  # noqa: E402
    PATH_EXCLUDE,                    # F3 경로 제외
    NOISE, IMPORT_ONLY,              # F4 노이즈 라인
    F6_MAX_DELETED_PER_COMMIT,       # F6 대량 변경 커밋 제외 (=30)
)
from build_dataset import derive_severity, extract_reason  # noqa: E402  (v1 FROZEN, import만)
import prompt_v2 as P  # noqa: E402

DATA = ROOT / "data"
OUT = ROOT / "out"
WORK = Path(os.environ.get("V2_WORK_DIR", "/tmp/v2_repos"))

SEED = 42  # §5-0 (v1과 동일 관례)

# ── 파일 확장자 → 언어 (build_dataset.py 의 LANG_MAP 과 같은 5개 언어) ──────────
EXT2LANG = {
    ".py": "Python",
    ".js": "JavaScript", ".jsx": "JavaScript", ".mjs": "JavaScript", ".cjs": "JavaScript",
    ".ts": "TypeScript", ".tsx": "TypeScript",
    ".java": "Java",
    ".php": "PHP", ".phtml": "PHP", ".inc": "PHP",
    ".c": "C", ".h": "C",
    ".cpp": "C++", ".cc": "C++", ".cxx": "C++", ".hpp": "C++", ".hh": "C++",
}
LANG_GROUP = {
    "Python": "Python", "JavaScript": "JS/TS", "TypeScript": "JS/TS",
    "Java": "Java", "PHP": "PHP", "C": "C/C++", "C++": "C/C++",
}
V4_LANG_MAP = {"python", "javascript", "typescript", "java", "php", "c", "c++", "cpp"}


# ── §5-0 재현 가능한 train/val 분할 ──────────────────────────────────────────
def split_bucket(cve_id: str) -> int:
    """수확 완료 순서·실행 시점과 무관한 결정론적 버킷 (§5-0).

    `random.shuffle(rest)` 를 쓰면 `rest` 리스트의 순서가 병렬 워커(8~12개)의 완료 순서에
    의존하게 되어 seed 를 고정해도 재현이 보장되지 않는다. 그래서 해시 기반으로 간다.
    """
    h = hashlib.sha256(f"{SEED}:{cve_id}".encode()).hexdigest()
    return int(h, 16) % 10


def assign_split(cve_id: str) -> str:
    """동일 CVE 의 모든 file-sample 은 반드시 같은 split 으로 간다 (§5-0)."""
    return "val" if split_bucket(cve_id) == 0 else "train"


# ── diff 파서 ────────────────────────────────────────────────────────────────
def parse_diff(diff: str) -> dict[str, dict]:
    """git show 의 diff 원문 → {pre-fix 경로: {"hunks":[[s,e]..], "deleted":[(라인번호, 원문)..]}}

    R4 `r4_cvefixes_harvest.deleted_lines_from_diff()` 와 `r4_cvefixes_filter.deleted_text_map()`
    두 로직을 한 번에 수행한다(후자는 filter.main() 안의 중첩 함수라 import 불가라 옮겨 적었다).
    라인 번호는 **취약본(pre-fix) 기준**이며, 이는 곧 `git show <hash>~1:<path>` 로 받는 파일의
    1-based 줄 번호와 동일 체계다 — 별도 변환이 필요 없다(§7. 암묵 가정하지 않고 여기 명시).

    키는 diff 의 `a/` 경로(=pre-fix 경로)다. 리네임된 파일은 `b/` 경로가 다르므로 별도로 담는다.
    """
    out: dict[str, dict] = {}
    cur = None
    old_ln = None
    for line in diff.splitlines():
        if line.startswith("diff --git"):
            m = re.search(r" a/(\S+) b/(\S+)$", line)
            if m:
                cur = m.group(1)
                out.setdefault(cur, {"hunks": [], "deleted": [], "post_path": m.group(2)})
            else:
                cur = None
            old_ln = None
            continue
        if cur is None:
            continue
        if line.startswith("@@"):
            m = re.match(r"@@ -(\d+)(?:,(\d+))?", line)
            if m:
                s = int(m.group(1))
                n = int(m.group(2) or 1)
                old_ln = s
                out[cur]["hunks"].append([s, max(s, s + n - 1)])
            continue
        if old_ln is None:
            continue
        if line.startswith("-") and not line.startswith("---"):
            out[cur]["deleted"].append((old_ln, line[1:]))
            old_ln += 1
        elif line.startswith("+") and not line.startswith("+++"):
            pass
        elif line.startswith("\\"):
            pass
        else:
            old_ln += 1
    return out


# ── git ──────────────────────────────────────────────────────────────────────
def _run(cmd, cwd=None, timeout=180):
    try:
        p = subprocess.run(cmd, cwd=cwd, capture_output=True, timeout=timeout)
        return p.returncode, p.stdout, p.stderr[-300:].decode("utf-8", "replace")
    except subprocess.TimeoutExpired:
        return -9, b"", "timeout"
    except Exception as e:  # noqa: BLE001
        return -8, b"", str(e)[:300]


def fetch_commit(owner: str, repo: str, sha: str,
                 d: Path | None = None) -> tuple[bool, str, Path]:
    """`git fetch --depth=2` 로 커밋과 그 부모만 받는다 (전체 클론보다 훨씬 싸다).

    --depth=2 라야 `<sha>~1`(부모)을 볼 수 있다 — pre-fix 파일 전문이 거기서 나온다.

    주의: 같은 레포 디렉터리에 여러 스레드가 동시에 `git init`/`fetch` 하면 경쟁 상태가 난다.
    그래서 호출부(main)는 **레포 단위로 묶어** 한 워커가 그 레포의 모든 커밋을 처리하게 한다.
    """
    if d is None:
        d = WORK / f"{owner}__{repo}"
    if not d.exists():
        d.mkdir(parents=True, exist_ok=True)
        rc, _, err = _run(["git", "init", "-q"], cwd=d)
        if rc != 0:
            return False, f"init:{err}", d
        _run(["git", "remote", "add", "origin",
              f"https://github.com/{owner}/{repo}.git"], cwd=d)
    rc, _, err = _run(["git", "fetch", "-q", "--depth=2", "origin", sha], cwd=d, timeout=240)
    if rc != 0:
        return False, f"fetch:{err}", d
    return True, "", d


def git_show_text(d: Path, ref: str) -> str | None:
    rc, out, _ = _run(["git", "show", ref], cwd=d, timeout=120)
    if rc != 0:
        return None
    return normalize_eol(out.decode("utf-8", "replace"))


def normalize_eol(s: str) -> str:
    """CRLF → LF 정규화.

    **줄 번호는 바뀌지 않는다** — `\\r\\n` 과 `\\n` 은 둘 다 한 줄을 끝내므로 줄 수가 동일하다.
    (홑 `\\r` 은 건드리지 않는다. 그건 줄 종결자로 해석하면 줄 수가 바뀌기 때문이다.)

    왜 필요한가: git diff 본문을 `splitlines()` 로 읽으면 줄 끝 `\\r` 이 이미 제거되는데,
    파일 전문은 `split("\\n")` 으로 나누면 `\\r` 이 남는다. 그래서 CRLF 파일에서
    "diff 의 삭제줄 원문" 과 "파일의 그 줄" 이 한 글자(`\\r`) 차이로 어긋난다 —
    PHASE 4 파일럿에서 실제로 2건 잡혔고, 둘 다 `rstrip('\\r')` 하면 완전 일치했다.
    즉 §7 의 줄번호 체계 동일성 전제가 깨진 게 아니라 줄끝 표기 문제였다.
    부수 효과로 CRLF 파일에서 줄마다 낭비되던 토큰 1개도 사라진다.
    """
    return s.replace("\r\n", "\n")


# ── §7 라벨 규칙 ─────────────────────────────────────────────────────────────
def f4_pass(text: str) -> bool:
    """F4 — 공백·주석만·닫는 괄호만·import 재배치 줄은 정답 후보에서 뺀다 (R4 정규식 그대로)."""
    return not (NOISE.match(text) or IMPORT_ONLY.match(text))


def select_line(hunks: list[list[int]], deleted: list[tuple[int, str]]) -> tuple[int | None, int]:
    """§7 의 ①~④ 를 그 순서 그대로 적용해 대표 LINE 을 고른다.

      ① diff 내 취약점 후보를 식별한다 — "같은 CWE 아래 서로 떨어진 hunk 묶음" 단위.
      ② selected_vulnerability_rule = highest_severity 로 대표 취약점 1개를 고른다.
      ③ 그 취약점 hunk 의 F 필터 통과 삭제줄만 후보 집합으로 좁힌다.
      ④ 그 안에서 line_selection_rule = first_deleted_line (가장 낮은 줄 번호).

    ①의 "hunk 묶음" 경계에 대하여 — 스펙은 임계값을 정의하지 않는다. 여기서는 **hunk 1개를
    후보 1개로** 둔다. 이는 임의 선택이 아니라 **결과가 증명 가능하게 동일**하기 때문이다:
      · severity 는 CVEfixes 에서 CVE 단위 값이라 한 CVE 안의 모든 후보가 동률이다
        (§7 도 이를 인정하고 "동률이면 더 낮은 hunk 시작 줄 번호"를 tie-break 로 못박았다).
      · 따라서 ②는 항상 "후보를 가진 가장 이른 hunk"를 고르고, ④는 그 안의 최소 줄을 고른다.
      · hunk 를 어떻게 묶든 '후보를 가진 가장 이른 hunk 의 최소 후보줄'이라는 답은 변하지 않는다.
    즉 정의되지 않은 자유 파라미터(묶음 임계값)를 새로 만들지 않으면서 §7 의 일반형을 만족한다.

    리턴: (선택된 LINE 또는 None, 그 줄의 diff 원문, 후보를 가진 취약점 후보 개수)
    """
    cand = [(ln, t) for ln, t in deleted if f4_pass(t)]
    if not cand:
        return None, None, 0
    text_of = dict(cand)

    def pick(lines: list[int]) -> tuple[int, str]:
        ln = min(lines)                                  # ④ first_deleted_line
        return ln, text_of[ln]

    if not hunks:
        # hunk 헤더를 못 읽은 경우에도 결정론을 유지한다.
        ln, t = pick([l for l, _ in cand])
        return ln, t, 1

    groups: list[tuple[int, list[int]]] = []   # (hunk 시작줄, 그 hunk 의 후보 줄들)
    for s, e in hunks:
        inside = [ln for ln, _ in cand if s <= ln <= e]
        if inside:
            groups.append((s, inside))
    if not groups:
        ln, t = pick([l for l, _ in cand])
        return ln, t, 1

    # ② severity 동률 → tie-break = 더 낮은 hunk 시작 줄 번호 (§7, 결정론)
    groups.sort(key=lambda g: g[0])
    ln, t = pick(groups[0][1])
    return ln, t, len(groups)


# ── 한 커밋 처리 ─────────────────────────────────────────────────────────────
def harvest_row(row: dict, cvemeta: dict, d: Path | None = None) -> dict:
    """v4_meta 한 행(=한 fix 커밋) → 그 커밋에서 나온 vuln/safe 샘플들 + 단계별 집계.

    `d` 가 주어지면 이미 준비된 레포 디렉터리를 쓴다(같은 레포의 여러 커밋을 한 워커가
    연달아 처리할 때). 없으면 여기서 fetch 한다.
    """
    cve, sha = row["cve_id"], row["hash"]
    owner, repo = row["owner"], row["repo"]
    rep = {"cve_id": cve, "hash": sha, "repo": f"{owner}/{repo}",
           "ok": False, "stage": None, "drops": [], "samples": [],
           "n_files_in_diff": 0, "n_ext_reject": 0, "ext_rejected": []}

    ok, err, d2 = fetch_commit(owner, repo, sha, d)
    d = d2
    if not ok:
        rep["stage"] = "fetch"
        rep["drops"].append(f"git_fetch_실패: {err[:120]}")
        return rep

    diff = git_show_text(d, sha)
    if diff is None:
        rep["stage"] = "show"
        rep["drops"].append("git_show_실패")
        return rep

    parsed = parse_diff(diff)
    rep["n_files_in_diff"] = len(parsed)

    # F7 — v4_meta 의 file_paths 에 있는 파일만
    fps = row.get("file_paths") or []
    if isinstance(fps, str):
        try:
            fps = ast.literal_eval(fps)
        except Exception:  # noqa: BLE001
            fps = []
    allow = set(fps or [])

    # 고려 대상 파일 확정 (F7 → F3 → 확장자)
    considered: dict[str, dict] = {}
    for path, info in parsed.items():
        if allow and path not in allow and info.get("post_path") not in allow:
            continue                                   # F7
        if PATH_EXCLUDE.search(path):
            continue                                   # F3
        ext = os.path.splitext(path)[1].lower()
        if ext not in EXT2LANG:                        # 5개 언어 밖 — 버리고 기록
            rep["n_ext_reject"] += 1
            rep["ext_rejected"].append(ext or "(none)")
            continue
        considered[path] = info

    if not considered:
        rep["stage"] = "F3/F7/ext"
        rep["drops"].append("고려 대상 파일 0")
        return rep

    # F6 — 커밋당 삭제 라인 상한 (고려 대상 파일 기준으로 센다. F1 제거에 따른 직접 대응물)
    n_deleted_total = sum(len(i["deleted"]) for i in considered.values())
    if n_deleted_total == 0:
        rep["stage"] = "F2"
        rep["drops"].append("F2 삭제 라인 0 (추가만 있는 수정)")
        return rep
    if n_deleted_total > F6_MAX_DELETED_PER_COMMIT:
        rep["stage"] = "F6"
        rep["drops"].append(f"F6 삭제 라인 {n_deleted_total} > {F6_MAX_DELETED_PER_COMMIT}")
        return rep

    # completion 재료 (CVEfixes 원본 메타)
    meta = cvemeta.get((cve, sha)) or cvemeta.get((cve, "")) or {}
    cwe_id = (row.get("cwe_id") or meta.get("cwe_id") or "").strip()
    cwe_name = (meta.get("cwe_name") or "").strip()
    reason = extract_reason(meta.get("cve_description"), meta.get("cwe_description") or "")

    cvss_raw = str(row.get("cvss3") or "").strip()
    cvss_present = cvss_raw not in ("", "nan", "None")
    sev, cvss_str = derive_severity(row.get("cvss3"), str(row.get("severity") or ""))

    # 파일별 후보 수 합계 = num_vulnerabilities_in_diff (메타, v3 다건 출력 대비)
    per_file_line: dict[str, tuple[int | None, str | None, int]] = {
        p: select_line(i["hunks"], i["deleted"]) for p, i in considered.items()
    }
    n_vuln_in_diff = sum(g for _, _, g in per_file_line.values())

    for path, info in considered.items():
        line, line_text, _ = per_file_line[path]
        if line is None:
            rep["drops"].append(f"F4 통과 삭제줄 0: {path}")
            continue
        lang = EXT2LANG[os.path.splitext(path)[1].lower()]
        post_path = info.get("post_path") or path

        pre = git_show_text(d, f"{sha}~1:{path}")
        post = git_show_text(d, f"{sha}:{post_path}")

        base = {
            "cve_id": cve, "repo": f"{owner}/{repo}", "fix_commit": sha,
            "file": path, "language": lang, "lang_group": LANG_GROUP[lang],
            "num_vulnerabilities_in_diff": n_vuln_in_diff,
            "selected_vulnerability_rule": "highest_severity",
            "line_selection_rule": "first_deleted_line",
            "cvss_source": "cvefixes_meta" if cvss_present else "missing",
            # v4_meta 는 v3 점수만 담고 minor 버전을 구분하지 않는다 → "3" 으로만 남긴다.
            "cvss_version": "3" if cvss_present else None,
            "severity": sev, "cvss_str": cvss_str,
            "cwe_name": cwe_name, "reason": reason,
            # §8-1 ±N 확정용 — 이 (CVE, 파일) 의 **F4 통과 삭제줄 전체**.
            # bench_v2.compute_N() 이 "삭제줄이 2개 이상인 그룹"만 모아 연속 간격의 중앙값을 낸다.
            # R4 8건 파일럿(중앙값 3.5)은 표본이 작아 못 쓰므로 전체 수확 데이터로 재계산해야 한다.
            "deleted_lines_all": sorted({ln for ln, t in info["deleted"] if f4_pass(t)}),
            "deleted_lines_raw_count": len(info["deleted"]),
        }

        if pre is not None:
            pre_lines = pre.split("\n")
            n_lines_pre = len(pre_lines)
            if line <= n_lines_pre:          # LINE > file_length 는 §10-1 fail-fast 대상
                rep["samples"].append({**base, "label": "vuln", "source": pre,
                                       "cwe": cwe_id or None, "line": line,
                                       "line_source": "deleted_line",
                                       # §7 의 "diff 줄번호 체계 = pre-fix 파일 줄번호 체계"라는
                                       # 전제를 audit 이 기계적으로 대조할 수 있도록 원문을 남긴다.
                                       # (암묵적으로 맞다고 가정하지 않는다 — §7 원문 요구)
                                       "line_text": line_text,
                                       "line_text_matches_file":
                                           pre_lines[line - 1] == line_text,
                                       "cvss": float(cvss_raw) if cvss_present else 0.0,
                                       "cvss_present": cvss_present})
            else:
                rep["drops"].append(
                    f"LINE {line} > pre-fix 파일 줄수 {n_lines_pre}: {path}")
        else:
            rep["drops"].append(f"pre-fix 전문 추출 실패: {path}")

        if post is not None:
            rep["samples"].append({**base, "label": "safe", "source": post,
                                   "file": post_path,
                                   "cwe": None, "line": 0, "line_source": "none",
                                   "cvss": 0.0, "cvss_present": False,
                                   "cvss_source": "missing", "cvss_version": None})
        else:
            rep["drops"].append(f"post-fix 전문 추출 실패: {post_path}")

    rep["ok"] = bool(rep["samples"])
    return rep


# ── 메인 ─────────────────────────────────────────────────────────────────────
def load_cvemeta() -> dict:
    p = DATA / "v2_cvemeta.jsonl"
    out = {}
    if p.exists():
        for line in p.open():
            try:
                r = json.loads(line)
            except json.JSONDecodeError:
                continue
            out[(r["cve_id"], r["hash"])] = r
    return out


def main() -> None:
    ap = argparse.ArgumentParser()
    ap.add_argument("--cohort", choices=["test", "trainval", "all"], default="all")
    ap.add_argument("--limit", type=int, default=0, help="0=제한 없음 (파일럿용)")
    ap.add_argument("--workers", type=int, default=10)
    ap.add_argument("--tag", default="")
    ap.add_argument("--only-repo", default="", help="owner/repo 하나만 수확 (예: torvalds/linux)")
    ap.add_argument("--repo-shards", type=int, default=1,
                    help="행이 많은 레포를 N 개 별도 디렉터리로 쪼개 병렬화")
    ap.add_argument("--shard-threshold", type=int, default=40,
                    help="이 행 수 이상인 레포만 샤딩한다")
    ap.add_argument("--skip-done", default="", help="이미 수확한 samples jsonl (중복 방지)")
    args = ap.parse_args()

    v1 = {}
    for sp in ("train", "val", "test"):
        v1[sp] = {json.loads(l)["meta"]["cve_id"] for l in (DATA / f"{sp}.jsonl").open()}

    rows = []
    for line in (DATA / "v4_meta.jsonl").open():
        r = json.loads(line)
        if (r.get("language") or "").strip().lower() not in V4_LANG_MAP:
            continue
        c = r["cve_id"]
        if c in v1["train"] or c in v1["val"]:
            continue                                  # v2 에서 전체 제외 (§3)
        r["_cohort"] = "test" if c in v1["test"] else "trainval"
        rows.append(r)

    if args.cohort != "all":
        rows = [r for r in rows if r["_cohort"] == args.cohort]
    if args.only_repo:
        o, rp = args.only_repo.split("/", 1)
        rows = [r for r in rows if r["owner"] == o and r["repo"] == rp]
    if args.skip_done and Path(args.skip_done).exists():
        done_keys = {(json.loads(l)["cve_id"], json.loads(l)["fix_commit"])
                     for l in Path(args.skip_done).open()}
        before = len(rows)
        rows = [r for r in rows if (r["cve_id"], r["hash"]) not in done_keys]
        print(f"[collect] 이미 수확된 {before - len(rows)}행 건너뜀", flush=True)
    # §4 우선순위: v1 test 641 을 최상위로 먼저 수확 → 그 다음 train/val 후보(JS/TS 우선)
    rows.sort(key=lambda r: (0 if r["_cohort"] == "test" else 1,
                             0 if (r.get("language") or "").lower() in
                                  ("javascript", "typescript") else 1,
                             r["cve_id"], r["hash"]))

    if args.limit:
        # 파일럿 표집은 **언어 비례**로 한다.
        # 위 정렬은 JS/TS 를 앞세우므로 그대로 앞에서 N개를 자르면 파일럿이 사실상 JS/TS 전용이
        # 된다(실측: 100건 → 샘플 227 중 225가 JS/TS). 그런데 이번 라운드의 핵심 변경은
        # **F1(JS/TS 게이트) 제거와 F5 미적용**이고 그 영향은 비-JS 언어에서 나타난다.
        # JS/TS 만 보는 파일럿은 그 변경을 검증하지 못하므로, 코호트의 언어 분포에 비례해
        # 결정론적으로 뽑는다. (전체 수확 시에는 --limit 을 안 쓰므로 이 경로가 안 탄다.)
        V4_TO_LANG = {"c": "C", "c++": "C++", "cpp": "C++", "python": "Python",
                      "javascript": "JavaScript", "typescript": "TypeScript",
                      "java": "Java", "php": "PHP"}

        def group_of(r: dict) -> str:
            return LANG_GROUP[V4_TO_LANG[(r["language"]).strip().lower()]]

        by_lang: dict[str, list[int]] = defaultdict(list)   # 그룹 → rows 인덱스
        for idx, r in enumerate(rows):
            by_lang[group_of(r)].append(idx)
        total = len(rows)
        chosen: set[int] = set()
        for lg in sorted(by_lang):
            quota = round(args.limit * len(by_lang[lg]) / total)
            chosen.update(by_lang[lg][:quota])
        # 반올림 오차 보정 (결정론적으로 앞에서 채운다 / 초과분은 뒤에서 자른다)
        for idx in range(len(rows)):
            if len(chosen) >= args.limit:
                break
            chosen.add(idx)
        rows = [rows[i] for i in sorted(chosen)[:args.limit]]
        dist = Counter(group_of(r) for r in rows)
        print("[collect] 파일럿 언어 비례 표집: "
              + ", ".join(f"{k} {v}" for k, v in sorted(dist.items())), flush=True)

    cvemeta = load_cvemeta()
    print(f"[collect] 대상 행 {len(rows)} / cvemeta {len(cvemeta)}건 로드 "
          f"/ workers={args.workers}", flush=True)
    WORK.mkdir(parents=True, exist_ok=True)
    OUT.mkdir(parents=True, exist_ok=True)

    tag = args.tag or args.cohort
    samples_path = DATA / f"v2_samples_raw{'_' + tag if tag else ''}.jsonl"
    report_path = OUT / f"v2_collect_report{'_' + tag if tag else ''}.json"

    # ── 레포 단위로 묶는다 ──────────────────────────────────────────────────
    # 이유 두 가지:
    #  (1) 디스크. 실측 결과 레포 크기가 극단적으로 편중돼 있다(작은 것 다수 + 177MB 짜리 하나).
    #      2,651건을 캐시로 쌓으면 여유 16GB 를 넘길 위험이 있어, 한 레포를 다 쓰면 **즉시 삭제**한다.
    #      피크 사용량이 (워커 수 × 최대 레포 크기) 로 묶인다.
    #  (2) 경쟁 상태. 같은 레포의 여러 커밋이 동시에 같은 디렉터리에 git init/fetch 하면 깨진다.
    by_repo: dict[tuple[str, str], list[dict]] = defaultdict(list)
    for r in rows:
        by_repo[(r["owner"], r["repo"])].append(r)

    # 레포 하나가 행을 아주 많이 가지면 워커 하나가 직렬로 다 처리해 병목이 된다
    # (실측: torvalds/linux 335행 × fetch 107초 = 9시간, 나머지 11개 워커는 유휴).
    # `--repo-shards N` 을 주면 그런 레포의 행을 N 개 **별도 디렉터리**로 쪼개 병렬화한다.
    # 디렉터리를 나누는 이유: 같은 디렉터리에 동시 fetch 하면 경쟁 상태가 난다.
    repo_jobs: list[tuple[tuple[str, str, int], list[dict]]] = []
    for (owner, repo), rs in sorted(by_repo.items()):
        nsh = args.repo_shards if (args.repo_shards > 1 and
                                   len(rs) >= args.shard_threshold) else 1
        if nsh == 1:
            repo_jobs.append(((owner, repo, 0), rs))
        else:
            for i in range(nsh):
                chunk = rs[i::nsh]
                if chunk:
                    repo_jobs.append(((owner, repo, i), chunk))
            print(f"[collect] {owner}/{repo}: {len(rs)}행 → {nsh} 샤드로 분할", flush=True)
    print(f"[collect] 작업 단위 {len(repo_jobs)}개 (고유 레포 {len(by_repo)}개)", flush=True)

    stats = Counter()
    ext_rejected = Counter()
    drops: list[dict] = []
    lock = Lock()
    t0 = time.time()
    done = 0

    def do_repo(key, rs):
        owner, repo, shard = key
        d = WORK / (f"{owner}__{repo}" if shard == 0 else f"{owner}__{repo}__s{shard}")
        reps = []
        try:
            for r in rs:
                try:
                    reps.append((r, harvest_row(r, cvemeta, d)))
                except Exception as e:  # noqa: BLE001
                    reps.append((r, {"cve_id": r["cve_id"], "hash": r["hash"], "ok": False,
                                     "stage": "exception", "drops": [str(e)[:200]],
                                     "samples": [], "n_ext_reject": 0, "ext_rejected": []}))
        finally:
            # 샘플은 이미 메모리에 뽑혔으므로 레포는 더 필요 없다 → 즉시 회수.
            shutil.rmtree(d, ignore_errors=True)
        return reps

    with samples_path.open("w") as fout, ThreadPoolExecutor(max_workers=args.workers) as ex:
        futs = [ex.submit(do_repo, k, rs) for k, rs in repo_jobs]
        for fut in as_completed(futs):
            for r, rep in fut.result():
                with lock:
                    done += 1
                    stats["rows"] += 1
                    stats["ok" if rep["ok"] else f"fail_{rep.get('stage') or 'nosample'}"] += 1
                    stats["ext_reject"] += rep.get("n_ext_reject", 0)
                    for e_ in rep.get("ext_rejected", []):
                        ext_rejected[e_] += 1
                    if rep["drops"]:
                        drops.append({"cve_id": rep["cve_id"], "hash": rep["hash"],
                                      "stage": rep.get("stage"), "drops": rep["drops"][:8]})
                    for s in rep["samples"]:
                        cohort = r["_cohort"]
                        s["split"] = "test" if cohort == "test" else assign_split(s["cve_id"])
                        s["test_cohort_source"] = "v1_test" if cohort == "test" else None
                        stats[f"sample_{s['label']}"] += 1
                        fout.write(json.dumps(s, ensure_ascii=False) + "\n")
                    if done % 25 == 0 or done == len(rows):
                        el = time.time() - t0
                        print(f"[collect] {done}/{len(rows)} ok={stats['ok']} "
                              f"samples={stats['sample_vuln']}v/{stats['sample_safe']}s "
                              f"({el:.0f}s)", flush=True)

    report = {
        "tag": tag, "cohort": args.cohort, "limit": args.limit,
        "n_rows": len(rows), "elapsed_sec": round(time.time() - t0, 1),
        "stats": dict(stats),
        "filters_applied": ["F2", "F3", "F4", "F6", "F7"],
        "filters_skipped": {
            "F1": "제거 — JS/TS 하드게이트라 5개 언어 중 4개가 수확 0건이 된다 (사용자 확정)",
            "F5": "전 언어 미적용 — CWE_SYNTAX 정규식이 Node 어휘라 타 언어에 오작동 (사용자 확정)",
        },
        "ext_rejected_counts": dict(ext_rejected),
        "ext_rejected_total": stats["ext_reject"],
        "drops_sample": drops[:200],
        "n_drop_records": len(drops),
        "samples_path": str(samples_path),
    }
    report_path.write_text(json.dumps(report, ensure_ascii=False, indent=2))
    print(json.dumps({k: v for k, v in report.items()
                      if k not in ("drops_sample",)}, ensure_ascii=False, indent=2))
    print(f"-> {samples_path}\n-> {report_path}")


if __name__ == "__main__":
    main()
