"""
ScanOps v4 — 파일 단위 원본 수집기
===================================
CVEfixes(HF hitoshura25/cvefixes)의 repo_url + fix commit hash로부터
  - 취약 버전 파일 전문 (fix 커밋의 부모 시점)
  - 패치 버전 파일 전문 (fix 커밋 시점)
  - 취약 hunk 줄 범위 (diff에서 파싱 — 파일 단위 벤치의 정답 줄)
를 수집한다.

2단계 구조 (재개 가능):
  python collect_files_v4.py harvest              # HF → data/v4_meta.jsonl (다운로드 없음, 수 분)
  python collect_files_v4.py download [N]         # meta → data/v4_files.jsonl (GitHub API+raw)

설계 결정
  - 커밋 dedup: 같은 (repo, hash)는 한 번만. 파일은 커밋당 최대 5개(초대형 커밋은 노이즈).
  - 우선순위: published_date 내림차순 — 벤치(2024+)가 먼저 완성되도록.
  - 부모 SHA는 commits API(시간당 5,000). raw.githubusercontent는 별도 예산.
  - 재개: 출력 파일의 (repo,hash,path) 키를 읽어 건너뜀. 실패도 기록해 재시도 안 함.
  - 파일 크기 200KB 초과 스킵(프롬프트에 어차피 못 실음), 삭제된 레포는 fail 기록.
"""
from __future__ import annotations

import json
import re
import sys
import time
import urllib.error
import urllib.parse
import urllib.request
from concurrent.futures import ThreadPoolExecutor, as_completed
from pathlib import Path

ROOT = Path(__file__).resolve().parent
DATA = ROOT / "data"
META = DATA / "v4_meta.jsonl"
OUT = DATA / "v4_files.jsonl"
FAIL = DATA / "v4_fail.jsonl"

EXT_OK = {".c", ".h", ".cc", ".cpp", ".hpp", ".cxx", ".py", ".js", ".jsx", ".ts", ".tsx",
          ".php", ".java", ".go", ".rb", ".rs"}
MAX_FILES_PER_COMMIT = 5
MAX_BYTES = 200_000

_tok = None


def token() -> str:
    global _tok
    if _tok is None:
        env = ROOT.parent / ".env"
        _tok = [l.split("=", 1)[1].strip() for l in env.read_text().splitlines()
                if l.startswith("GITHUB_TOKEN=")][0]
    return _tok


def http(url: str, gh_api: bool = False, tries: int = 3) -> bytes | None:
    hdr = {"User-Agent": "scanops-v4"}
    if gh_api:
        hdr |= {"Authorization": f"Bearer {token()}", "Accept": "application/vnd.github+json"}
    for i in range(tries):
        try:
            with urllib.request.urlopen(urllib.request.Request(url, headers=hdr), timeout=30) as r:
                # API 잔량이 바닥나면 리셋까지 대기 (다운로드는 밤새 돌므로 기다리면 됨)
                rem = r.headers.get("X-RateLimit-Remaining")
                if gh_api and rem is not None and int(rem) < 20:
                    reset = int(r.headers.get("X-RateLimit-Reset", time.time() + 300))
                    wait = max(0, reset - time.time()) + 5
                    print(f"[rate] API 잔량 {rem} — {wait:.0f}s 대기", flush=True)
                    time.sleep(wait)
                return r.read()
        except urllib.error.HTTPError as e:
            if e.code in (404, 451):        # 삭제·비공개·법적차단 → 재시도 무의미
                return None
            if e.code == 403:               # rate limit → 헤더 보고 대기
                reset = int(e.headers.get("X-RateLimit-Reset", time.time() + 300))
                time.sleep(max(0, reset - time.time()) + 5)
                continue
            time.sleep(2 * (i + 1))
        except Exception:
            time.sleep(2 * (i + 1))
    return None


def parse_hunks(diff: str) -> dict[str, list[list[int]]]:
    """diff 전체 → {파일경로: [[old_start, old_end], ...]} (취약본 기준 줄 범위)"""
    out: dict[str, list[list[int]]] = {}
    cur = None
    for line in diff.splitlines():
        if line.startswith("diff --git"):
            m = re.search(r" a/(\S+) b/(\S+)$", line)
            cur = m.group(1) if m else None
        elif line.startswith("@@") and cur:
            m = re.match(r"@@ -(\d+)(?:,(\d+))?", line)
            if m:
                s = int(m.group(1))
                n = int(m.group(2) or 1)
                out.setdefault(cur, []).append([s, max(s, s + n - 1)])
    return out


def harvest() -> None:
    from datasets import load_dataset
    ds = load_dataset("hitoshura25/cvefixes", split="train", streaming=True)
    n = 0
    with META.open("w") as f:
        for r in ds:
            m = re.match(r"https?://github\.com/([^/]+)/([^/]+?)(?:\.git)?/?$",
                         r.get("repo_url") or "")
            if not m:
                continue
            fps = r.get("file_paths") or []
            if isinstance(fps, str):
                try:
                    import ast
                    fps = ast.literal_eval(fps)
                except Exception:
                    fps = []
            fps = [p for p in fps if Path(p).suffix.lower() in EXT_OK][:MAX_FILES_PER_COMMIT]
            if not fps:
                continue
            f.write(json.dumps({
                "owner": m.group(1), "repo": m.group(2), "hash": r["hash"],
                "cve_id": r["cve_id"], "cwe_id": r.get("cwe_id") or "",
                "language": r.get("language") or "", "severity": str(r.get("severity") or ""),
                "published_date": r.get("published_date") or "",
                "cvss3": str(r.get("cvss3_base_score") or ""),
                "file_paths": fps,
                "hunks": parse_hunks(r.get("diff_with_context") or ""),
            }, ensure_ascii=False) + "\n")
            n += 1
            if n % 2000 == 0:
                print(f"harvest {n}", flush=True)
    print(f"HARVEST_DONE {n}")


def load_done() -> set[tuple]:
    done = set()
    for p in (OUT, FAIL):
        if p.exists():
            for l in p.open():
                try:
                    r = json.loads(l)
                    done.add((r["owner"], r["repo"], r["hash"], r.get("path", "")))
                except Exception:
                    pass
    return done


def fetch_commit(rec: dict) -> list[dict]:
    """한 커밋 → 파일 레코드 목록 (성공/실패 모두 기록용)."""
    o, rp, h = rec["owner"], rec["repo"], rec["hash"]
    api = http(f"https://api.github.com/repos/{o}/{rp}/commits/{h}", gh_api=True)
    if api is None:
        return [{"owner": o, "repo": rp, "hash": h, "path": "", "fail": "commit_404"}]
    parents = json.loads(api).get("parents") or []
    if not parents:
        return [{"owner": o, "repo": rp, "hash": h, "path": "", "fail": "no_parent"}]
    par = parents[0]["sha"]
    rows = []
    for path in rec["file_paths"]:
        q = urllib.parse.quote(path)
        old = http(f"https://raw.githubusercontent.com/{o}/{rp}/{par}/{q}")
        new = http(f"https://raw.githubusercontent.com/{o}/{rp}/{h}/{q}")
        if not old or not new or len(old) > MAX_BYTES or len(new) > MAX_BYTES:
            rows.append({"owner": o, "repo": rp, "hash": h, "path": path,
                         "fail": "file_miss_or_big"})
            continue
        try:
            old_t, new_t = old.decode("utf-8", "replace"), new.decode("utf-8", "replace")
        except Exception:
            rows.append({"owner": o, "repo": rp, "hash": h, "path": path, "fail": "decode"})
            continue
        rows.append({"owner": o, "repo": rp, "hash": h, "parent": par, "path": path,
                     "cve_id": rec["cve_id"], "cwe_id": rec["cwe_id"],
                     "language": rec["language"], "severity": rec["severity"],
                     "published_date": rec["published_date"], "cvss3": rec["cvss3"],
                     "hunks_old": rec["hunks"].get(path, []),
                     "vuln_file": old_t, "fixed_file": new_t})
    return rows


def download(limit: int | None) -> None:
    metas = [json.loads(l) for l in META.open()]
    # 커밋 dedup + 벤치 우선(최신 먼저)
    seen, commits = set(), []
    for r in sorted(metas, key=lambda x: x["published_date"], reverse=True):
        k = (r["owner"], r["repo"], r["hash"])
        if k not in seen:
            seen.add(k)
            commits.append(r)
    done = load_done()
    todo = [c for c in commits
            if any((c["owner"], c["repo"], c["hash"], p) not in done for p in c["file_paths"])
            and (c["owner"], c["repo"], c["hash"], "") not in done]
    if limit:
        todo = todo[:limit]
    print(f"커밋 {len(commits)}개 중 대기 {len(todo)}개 (완료/실패 {len(done)}건 스킵)", flush=True)

    ok = fail = 0
    t0 = time.time()
    with OUT.open("a") as fo, FAIL.open("a") as ff, ThreadPoolExecutor(8) as ex:
        futs = {ex.submit(fetch_commit, c): c for c in todo}
        for i, fut in enumerate(as_completed(futs), 1):
            for row in fut.result():
                if "fail" in row:
                    ff.write(json.dumps(row) + "\n")
                    fail += 1
                else:
                    fo.write(json.dumps(row, ensure_ascii=False) + "\n")
                    ok += 1
            if i % 50 == 0:
                el = time.time() - t0
                print(f"[{i}/{len(todo)}] 파일 ok={ok} fail={fail} "
                      f"({el:.0f}s, {i/el*3600:.0f} commits/hr)", flush=True)
                fo.flush(); ff.flush()
    print(f"DOWNLOAD_DONE ok={ok} fail={fail}")


if __name__ == "__main__":
    cmd = sys.argv[1] if len(sys.argv) > 1 else "harvest"
    if cmd == "harvest":
        harvest()
    else:
        download(int(sys.argv[2]) if len(sys.argv) > 2 else None)
