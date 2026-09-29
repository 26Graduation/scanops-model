import json
import math
import sys
from pathlib import Path

import faiss
import chromadb
from chromadb.config import Settings

BASE_DIR = Path(__file__).resolve().parent.parent
FAISS_PATH = BASE_DIR / "data" / "cve_index.faiss"
JSON_PATH  = BASE_DIR / "data" / "nvdcve-2.0-preprocessed.json"
CHROMA_DIR = BASE_DIR / "chroma_db"

BATCH_SIZE = 100
COLLECTION_NAME = "cve_collection"


def load_cves(path: Path) -> list[dict]:
    with open(path, encoding="utf-8") as f:
        return json.load(f)


def extract_vectors(index_path: Path) -> list[list[float]]:
    index = faiss.read_index(str(index_path))
    n = index.ntotal
    print(f"[FAISS] 총 벡터 수: {n}")
    vectors = index.reconstruct_n(0, n)
    return vectors.tolist()


def build_metadata(cve: dict) -> dict:
    return {
        "severity":      str(cve.get("severity") or ""),
        "score":         float(cve.get("score") or 0.0),
        "cwe_primary":   str(cve.get("cwe_primary") or ""),
        "published":     str(cve.get("published") or ""),
        "score_version": str(cve.get("score_version") or ""),
    }


def main():
    print("=== FAISS → ChromaDB 마이그레이션 시작 ===\n")

    cves = load_cves(JSON_PATH)
    vectors = extract_vectors(FAISS_PATH)

    if len(cves) != len(vectors):
        print(f"[ERROR] CVE 수({len(cves)})와 벡터 수({len(vectors)})가 다릅니다.", file=sys.stderr)
        sys.exit(1)

    client = chromadb.PersistentClient(path=str(CHROMA_DIR))

    # 기존 컬렉션이 있으면 삭제 후 재생성
    existing = [c.name for c in client.list_collections()]
    if COLLECTION_NAME in existing:
        client.delete_collection(COLLECTION_NAME)
        print(f"[Chroma] 기존 컬렉션 '{COLLECTION_NAME}' 삭제됨")

    collection = client.create_collection(
        name=COLLECTION_NAME,
        metadata={"hnsw:space": "cosine"},
    )
    print(f"[Chroma] 컬렉션 '{COLLECTION_NAME}' 생성 완료\n")

    total = len(cves)
    n_batches = math.ceil(total / BATCH_SIZE)

    for batch_idx in range(n_batches):
        start = batch_idx * BATCH_SIZE
        end   = min(start + BATCH_SIZE, total)
        batch = cves[start:end]

        collection.add(
            ids        = [c["id"] for c in batch],
            embeddings = vectors[start:end],
            documents  = [str(c.get("description") or "") for c in batch],
            metadatas  = [build_metadata(c) for c in batch],
        )
        print(f"  배치 {batch_idx + 1}/{n_batches} 삽입 완료 ({start + 1}–{end} / {total})")

    count = collection.count()
    print(f"\n=== 마이그레이션 완료 ===")
    print(f"ChromaDB 저장 경로: {CHROMA_DIR}")
    print(f"컬렉션 '{COLLECTION_NAME}' 문서 수: {count}")


if __name__ == "__main__":
    main()
