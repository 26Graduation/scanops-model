"""Phase B-0 — 레포 벤치 **정답표** 생성기 (스캔 결과를 보기 전에 돈다)

juice-shop 은 소스 안에 **공식 라인 마커**를 갖고 있다:

    ... // vuln-code-snippet vuln-line <challengeKey> [<challengeKey> ...]

이 마커는 juice-shop 의 "Coding Challenge" 기능이 정답 판정에 쓰는 값이다
(`lib/codingChallenges.ts:76` 이 같은 정규식으로 읽는다). 즉 **레포 자신이 관리하는
파일:라인 단위 정답**이고, 우리가 고른 값이 아니다 → confidence = high.

카테고리는 `data/static/challenges.yml` 의 `key → category` 로 붙인다.

**cross_file 은 이 스크립트가 정하지 않는다.** 여기서는 후보 신호만 계산해서
`cross_file_candidate` 로 싣고, 사람이 확인한 값은 별도 주석 파일
(`{repo}_crossfile.json`)에서 병합한다. 확인되지 않은 건은 cross_file=false 로 둔다.
(정답표를 우리 도구에 유리하게 만들지 않기 위한 절차다.)

실행:
    python3 rebuild/repo_bench_truth.py juice-shop /tmp/scanops_repobench/juice-shop
출력:
    rebuild/data/repo_bench/{repo}_truth.jsonl
    rebuild/data/repo_bench/{repo}_truth_stats.json
"""
from __future__ import annotations

import json
import re
import subprocess
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent
OUT_DIR = ROOT / "data" / "repo_bench"

VULN_LINE = re.compile(r"vuln-code-snippet\s+vuln-line\s+(.+?)\s*$")

# 정답표에서 제외할 경로 — 정답 자체(codefixes)·테스트·리포트 생성기·에이전트 문서
EXCLUDE_PARTS = ("/codefixes/", "/test/", "/rsn/", "/.ai/", "node_modules")
# 소스 코드가 아닌 파일(설정·데이터)은 별도 표시만 하고 코드 스캔 대상에서 빼기 쉽게 둔다
CODE_SUFFIXES = {".ts", ".js", ".tsx", ".jsx", ".java", ".py", ".php", ".sol", ".go"}

REPO_URL = {
    "juice-shop": "https://github.com/juice-shop/juice-shop/blob/{sha}/{path}#L{line}",
    "WebGoat": "https://github.com/WebGoat/WebGoat/blob/{sha}/{path}#L{line}",
    "pygoat": "https://github.com/adeyosemanputra/pygoat/blob/{sha}/{path}#L{line}",
}


def _sha(repo_dir: Path) -> str:
    return subprocess.run(["git", "-C", str(repo_dir), "rev-parse", "HEAD"],
                          capture_output=True, text=True).stdout.strip()


def _challenge_meta(repo_dir: Path) -> dict[str, dict]:
    """challenges.yml → {key: {name, category, mitigationUrl}}  (yaml 없이 파싱)."""
    path = repo_dir / "data" / "static" / "challenges.yml"
    if not path.exists():
        return {}
    meta: dict[str, dict] = {}
    cur: dict = {}
    for line in path.read_text(encoding="utf-8", errors="replace").splitlines():
        s = line.strip()
        m = re.match(r"^(name|category|key|mitigationUrl):\s*'?(.*?)'?\s*$", s)
        if not m:
            continue
        field, value = m.group(1), m.group(2)
        if field == "name":
            cur = {"name": value}
        elif field == "key":
            cur["key"] = value
            meta[value] = cur
        else:
            cur[field] = value
    return meta


def _iter_files(repo_dir: Path):
    for p in repo_dir.rglob("*"):
        if not p.is_file():
            continue
        rel = "/" + str(p.relative_to(repo_dir))
        if any(part in rel for part in EXCLUDE_PARTS):
            continue
        if p.stat().st_size > 2_000_000:
            continue
        yield p, rel.lstrip("/")


def _imports_of(text: str) -> set[str]:
    """이 파일이 끌어오는 로컬 모듈 경로(상대 import)."""
    out = set()
    for m in re.finditer(r"""(?:from\s+|require\()\s*['"](\.[^'"]+)['"]""", text):
        out.add(m.group(1))
    return out


def build(repo: str, repo_dir: Path) -> None:
    sha = _sha(repo_dir)
    meta = _challenge_meta(repo_dir)
    rows: list[dict] = []
    seen: set[tuple[str, int, str]] = set()

    for path, rel in _iter_files(repo_dir):
        try:
            text = path.read_text(encoding="utf-8", errors="replace")
        except OSError:
            continue
        if "vuln-code-snippet" not in text:
            continue
        lines = text.splitlines()
        imports = _imports_of(text)
        for i, line in enumerate(lines, start=1):
            m = VULN_LINE.search(line)
            if not m:
                continue
            for key in m.group(1).split():
                if (rel, i, key) in seen:
                    continue
                seen.add((rel, i, key))
                info = meta.get(key, {})
                # cross_file 후보 신호: 이 라인이 로컬 import 로 들어온 심볼을 부른다
                cand = bool(imports) and bool(re.search(r"\b\w+\.\w+\s*\(", line))
                rows.append({
                    "id": f"{repo}:{key}:{rel}:{i}",
                    "repo": repo,
                    "challenge_key": key,
                    "name": info.get("name", ""),
                    "category": info.get("category", ""),
                    "sink_file": rel,
                    "sink_line": i,
                    "source_file": None,
                    "source_line": None,
                    "cross_file": False,           # 사람이 확인한 값만 true 로 바꾼다
                    "cross_file_candidate": cand,  # 자동 신호(판정에 쓰지 않는다)
                    "confidence": "high",          # 레포 자신이 관리하는 파일:라인 마커
                    "is_code_file": path.suffix in CODE_SUFFIXES,
                    "evidence_url": REPO_URL[repo].format(sha=sha, path=rel, line=i),
                    "evidence_kind": "in-repo official marker (vuln-code-snippet vuln-line)",
                    "mitigation_url": info.get("mitigationUrl", ""),
                    "line_text": line.strip()[:300],
                })

    # 사람이 확인한 cross_file 주석 병합 (있을 때만)
    ann_path = OUT_DIR / f"{repo}_crossfile.json"
    if ann_path.exists():
        ann = json.loads(ann_path.read_text())
        by_id = {r["id"]: r for r in rows}
        for rid, a in ann.items():
            if rid in by_id:
                by_id[rid].update({
                    "cross_file": bool(a.get("cross_file")),
                    "source_file": a.get("source_file"),
                    "source_line": a.get("source_line"),
                    "confidence": a.get("confidence", by_id[rid]["confidence"]),
                    "note": a.get("note", ""),
                })

    OUT_DIR.mkdir(parents=True, exist_ok=True)
    out = OUT_DIR / f"{repo}_truth.jsonl"
    with out.open("w") as f:
        for r in sorted(rows, key=lambda r: (r["sink_file"], r["sink_line"], r["challenge_key"])):
            f.write(json.dumps(r, ensure_ascii=False) + "\n")

    stats = {
        "repo": repo, "commit": sha, "n": len(rows),
        "n_code_file": sum(1 for r in rows if r["is_code_file"]),
        "n_cross_file": sum(1 for r in rows if r["cross_file"]),
        "n_cross_file_candidate": sum(1 for r in rows if r["cross_file_candidate"]),
        "by_confidence": {c: sum(1 for r in rows if r["confidence"] == c)
                          for c in ("high", "med", "low")},
        "by_category": {},
        "files": sorted({r["sink_file"] for r in rows}),
    }
    for r in rows:
        stats["by_category"][r["category"] or "(none)"] = \
            stats["by_category"].get(r["category"] or "(none)", 0) + 1
    (OUT_DIR / f"{repo}_truth_stats.json").write_text(
        json.dumps(stats, ensure_ascii=False, indent=2))
    print(json.dumps(stats, ensure_ascii=False, indent=2))
    print(f"저장: {out}")


if __name__ == "__main__":
    build(sys.argv[1], Path(sys.argv[2]))
