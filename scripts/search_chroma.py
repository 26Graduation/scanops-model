from pathlib import Path

import chromadb
from sentence_transformers import SentenceTransformer

BASE_DIR    = Path(__file__).resolve().parent.parent
CHROMA_DIR  = BASE_DIR / "chroma_db"
MODEL_NAME  = "BAAI/bge-small-en-v1.5"
BGE_PREFIX  = "Represent this sentence for searching relevant passages: "
COLLECTION  = "cve_collection"
TOP_K       = 5


def embed(model: SentenceTransformer, query: str) -> list[float]:
    return model.encode(BGE_PREFIX + query, normalize_embeddings=True).tolist()


def print_results(results: dict, label: str) -> None:
    print(f"\n{'='*60}")
    print(f"검색: {label}")
    print(f"{'='*60}")
    ids       = results["ids"][0]
    metas     = results["metadatas"][0]
    docs      = results["documents"][0]
    distances = results["distances"][0]

    for rank, (cve_id, meta, doc, dist) in enumerate(zip(ids, metas, docs, distances), 1):
        print(f"\n[{rank}] {cve_id}  similarity={1 - dist:.4f}")
        print(f"  severity : {meta.get('severity')}  score={meta.get('score')}")
        print(f"  desc     : {doc[:100]}...")


def main():
    print("ChromaDB 및 임베딩 모델 로드 중...")
    client     = chromadb.PersistentClient(path=str(CHROMA_DIR))
    collection = client.get_collection(COLLECTION)
    model      = SentenceTransformer(MODEL_NAME)

    print(f"컬렉션 문서 수: {collection.count()}")

    query = "SQL injection bypass authentication"
    vec   = embed(model, query)

    # 필터 없는 검색
    results = collection.query(
        query_embeddings=[vec],
        n_results=TOP_K,
        include=["documents", "metadatas", "distances"],
    )
    print_results(results, f'"{query}" (필터 없음, 상위 {TOP_K}개)')

    # severity=HIGH 필터 검색
    results_high = collection.query(
        query_embeddings=[vec],
        n_results=TOP_K,
        where={"severity": {"$eq": "HIGH"}},
        include=["documents", "metadatas", "distances"],
    )
    print_results(results_high, f'"{query}" (severity=HIGH, 상위 {TOP_K}개)')

    print("\n=== 검색 테스트 완료 ===")


if __name__ == "__main__":
    main()
