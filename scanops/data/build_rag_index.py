"""NVD → Qdrant RAG 인덱스 재구축 (무효/반려 필터 + dedup + 전체 재임베딩)
================================================================
배경: 기존 Qdrant `cve_vulnerabilities` 컬렉션엔 792개만 임베딩돼 있었으나
      로컬 NVD 피드(data/nvdcve-2.0-live.json)엔 9,134개(전부 2026 CVE)가 있다.
      → 가진 데이터의 8.7%만 사용. 게다가 피드엔 반려(REJECT)·분쟁(DISPUTED)
      항목이 섞여 있고, prepare.py 의 preprocessed 적재 경로는 상태 필터를
      타지 않아 그대로 임베딩되는 버그가 있었다.

이 스크립트가 하는 일 (★"무효·반려는 무조건 제외"):
  1. 무효 필터 — 설명문이 ** REJECT / DISPUTED / RESERVED / UNSUPPORTED **
     placeholder 거나 비어있거나 너무 짧으면(<40자) 제외.
  2. dedup — cve_id 중복 + 정규화 설명문 해시 중복 제거.
  3. 전체 재임베딩 — BGE-small 로 설명문 임베딩 후 컬렉션을 **재생성**해 적재.

실행:
  python -m scanops.data.build_rag_index            # live.json 전체 재임베딩
  python -m scanops.data.build_rag_index --input data/nvdcve-2.0-live.json --dry-run
"""
from __future__ import annotations

import argparse
import hashlib
import json
import os
import re
from collections import Counter
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]

QDRANT_URL = os.getenv("QDRANT_URL", "http://localhost:6333")
COLLECTION = os.getenv("QDRANT_COLLECTION", "cve_vulnerabilities")
VECTOR_DIM = 384            # bge-small-en-v1.5
BATCH = 128
MIN_DESC_LEN = 40
DEFAULT_INPUT = ROOT / "data" / "nvdcve-2.0-live.json"

# ** REJECT **, **DISPUTED**, ** RESERVED **, ** UNSUPPORTED WHEN ASSIGNED ** 등
_INVALID_RE = re.compile(r"\*\*\s*(REJECT|DISPUTED|RESERVED|UNSUPPORTED)", re.I)


def _norm(s: str) -> str:
    return re.sub(r"\s+", " ", s or "").strip().lower()


def _is_invalid(desc: str) -> bool:
    d = (desc or "").strip()
    if len(d) < MIN_DESC_LEN:
        return True
    if _INVALID_RE.search(d):
        return True
    if "DO NOT USE THIS CANDIDATE" in d.upper():
        return True
    return False


def _year(s: str) -> str:
    m = re.match(r"(\d{4})", str(s or ""))
    return m.group(1) if m else ""


def clean_records(rows: list[dict]) -> tuple[list[dict], Counter]:
    """무효/반려 제거 + dedup. (정제 레코드, 사유별 카운트) 반환."""
    stats: Counter = Counter()
    seen_id: set[str] = set()
    seen_desc: set[str] = set()
    out: list[dict] = []
    for r in rows:
        cid = (r.get("cve_id") or r.get("id") or "").strip()
        desc = (r.get("description") or "").strip()
        if not cid:
            stats["no_id"] += 1
            continue
        if _is_invalid(desc):
            stats["invalid_or_rejected"] += 1
            continue
        if cid in seen_id:
            stats["dup_id"] += 1
            continue
        dh = hashlib.sha1(_norm(desc).encode()).hexdigest()
        if dh in seen_desc:
            stats["dup_desc"] += 1
            continue
        seen_id.add(cid)
        seen_desc.add(dh)
        cwe = r.get("cwe") or []
        if isinstance(cwe, str):
            cwe = [cwe]
        out.append({
            "cve_id": cid,
            "published": r.get("published", "")[:10],
            "year": _year(r.get("published")),
            "cwe": cwe,
            "cwe_primary": cwe[0] if cwe else None,
            "cvss": r.get("cvss"),
            "severity": r.get("severity"),
            "description": desc,
        })
        stats["kept"] += 1
    return out, stats


def embed_and_store(records: list[dict], recreate: bool) -> int:
    from qdrant_client import QdrantClient
    from qdrant_client.models import Distance, PointStruct, VectorParams
    from scanops.core.embedder import embed_documents

    client = QdrantClient(url=QDRANT_URL, timeout=60)
    existing = {c.name for c in client.get_collections().collections}
    if COLLECTION in existing and recreate:
        print(f"[rag] 기존 컬렉션 '{COLLECTION}' 삭제 후 재생성")
        client.delete_collection(COLLECTION)
    if COLLECTION not in existing or recreate:
        client.create_collection(
            collection_name=COLLECTION,
            vectors_config=VectorParams(size=VECTOR_DIM, distance=Distance.COSINE),
        )

    uploaded = 0
    from tqdm import tqdm
    for start in tqdm(range(0, len(records), BATCH), desc="Qdrant 적재"):
        batch = records[start:start + BATCH]
        vecs = embed_documents([r["description"] for r in batch])
        points = [
            PointStruct(id=start + i, vector=vec, payload=rec)
            for i, (rec, vec) in enumerate(zip(batch, vecs))
        ]
        client.upsert(collection_name=COLLECTION, points=points)
        uploaded += len(points)
    return uploaded


def main() -> None:
    ap = argparse.ArgumentParser()
    ap.add_argument("--input", type=Path, default=DEFAULT_INPUT)
    ap.add_argument("--dry-run", action="store_true", help="정제만 하고 임베딩은 건너뜀")
    ap.add_argument("--no-recreate", action="store_true", help="컬렉션 재생성 없이 upsert")
    a = ap.parse_args()

    rows = json.loads(a.input.read_text(encoding="utf-8"))
    if isinstance(rows, dict):
        rows = rows.get("data", rows.get("vulnerabilities", []))
    print(f"[rag] 입력 {len(rows)}개 ← {a.input.name}")

    records, stats = clean_records(rows)
    print("─" * 60)
    print("정제 결과:")
    for k in ("kept", "invalid_or_rejected", "dup_id", "dup_desc", "no_id"):
        print(f"  {k:22s}: {stats.get(k, 0)}")
    yrs = Counter(r["year"] for r in records)
    print("  연도:", dict(sorted(yrs.items())))
    with_cwe = sum(1 for r in records if r["cwe"])
    with_cvss = sum(1 for r in records if r["cvss"] is not None)
    print(f"  CWE 있음: {with_cwe} | CVSS 있음: {with_cvss}")

    if a.dry_run:
        print("[rag] --dry-run: 임베딩 건너뜀")
        return

    n = embed_and_store(records, recreate=not a.no_recreate)
    print("─" * 60)
    print(f"[rag] 임베딩·적재 완료: {n:,}개 → {QDRANT_URL} (collection={COLLECTION})")


if __name__ == "__main__":
    main()
