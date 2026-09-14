"""sanitizers.json → Joern 스크립트가 읽는 sanFile 텍스트로 변환.

형식: "<category>\t<regex>" 한 줄씩. category "_any" 는 전 카테고리 공통.
언어별 블록(JAVASRC/PYTHONSRC/JSSRC)은 common 위에 **덧붙인다**(교체 아님).
"""
from __future__ import annotations

import json
from pathlib import Path

SPEC_PATH = Path(__file__).resolve().parent / "sanitizers.json"


def load_spec(path: Path | None = None) -> dict:
    return json.loads((path or SPEC_PATH).read_text())


def patterns_for(lang: str, spec: dict | None = None) -> dict[str, list[dict]]:
    """joern_lang(JAVASRC 등) → {block_category: [{"re":..., "applies_to":[...]}, ...]}

    v4: 값이 문자열이 아니라 dict 다. 매칭은 block_category 가 아니라
    applies_to 로 한다(§8 D-1).
    """
    spec = spec or load_spec()
    out: dict[str, list[dict]] = {}
    for block_name in ("common", lang):
        block = spec.get(block_name) or {}
        for cat, pats in block.items():
            if cat.startswith("_") and cat != "_any":
                continue  # _note 등 메타
            if not isinstance(pats, list):
                continue
            out.setdefault(cat, []).extend(pats)
    return out


def write_san_file(lang: str, dest: Path, spec: dict | None = None) -> int:
    """sanFile 을 dest 에 쓰고 줄 수를 반환.

    v4 형식: "<블록카테고리>\t<applies_to,콤마구분>\t<regex>"
    """
    pats = patterns_for(lang, spec)
    lines = []
    for cat, ps in sorted(pats.items()):
        for p in ps:
            if isinstance(p, str):        # 구형식 안전장치
                p = {"re": p, "applies_to": [cat]}
            ap = ",".join(p.get("applies_to") or ["*"])
            lines.append(f"{cat}\t{ap}\t{p['re']}")
    dest.write_text("\n".join(lines) + "\n")
    return len(lines)


if __name__ == "__main__":
    import sys
    lang = sys.argv[1] if len(sys.argv) > 1 else "JAVASRC"
    spec = load_spec()
    pats = patterns_for(lang, spec)
    total = sum(len(v) for v in pats.values())
    print(f"{lang}: {len(pats)} categories, {total} patterns")
    for cat, ps in sorted(pats.items()):
        print(f"  {cat:12s} {len(ps)}")
