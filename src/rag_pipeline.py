"""
CVE RAG 파이프라인

[흐름]
사용자 질문
  → ① 쿼리 임베딩  (bge-small-en-v1.5)
  → ② Qdrant 검색  (유사 CVE top-k)
  → ③ 컨텍스트 구성 (검색 결과 포맷팅)
  → ④ 프롬프트 조립 (페르소나 + 컨텍스트 + 질문)
  → ⑤ Gemma 호출   (Ollama REST API)
  → 최종 응답 출력

실행 전 필요 서비스:
  - Qdrant : docker run -d --name qdrant -p 6333:6333 qdrant/qdrant
  - Ollama : brew services start ollama
"""

import requests
from sentence_transformers import SentenceTransformer
from qdrant_client import QdrantClient
from qdrant_client.models import Filter, FieldCondition, MatchValue

# ── 설정 ───────────────────────────────────────────────────
EMBED_MODEL     = "BAAI/bge-small-en-v1.5"
QDRANT_URL      = "http://localhost:6333"
COLLECTION_NAME = "cve_vulnerabilities"
OLLAMA_URL      = "http://localhost:11434/api/generate"
LLM_MODEL       = "gemma2:2b"
TOP_K           = 5   # Qdrant에서 가져올 유사 CVE 수


# ── 페르소나 (시스템 프롬프트) ─────────────────────────────
SYSTEM_PERSONA = """You are a cybersecurity vulnerability expert with deep knowledge of CVE databases and security analysis.

Your responsibilities:
- Always present AT LEAST 3 vulnerabilities when answering
- For each vulnerability, provide: CVE ID, severity, attack vector, and a brief risk explanation
- Prioritize CRITICAL and HIGH severity vulnerabilities
- Give practical remediation advice
- Be concise but thorough

Answer in the same language as the user's question."""


# ════════════════════════════════════════════════════════════
# 단계 ① : 쿼리 임베딩
# ════════════════════════════════════════════════════════════
def embed_query(model: SentenceTransformer, query: str) -> list[float]:
    """
    사용자 질문을 벡터로 변환.
    임베딩 때와 동일한 모델 + normalize=True 를 사용해야
    Qdrant의 코사인 유사도 검색과 공간이 일치함.
    """
    vector = model.encode(
        [query],
        normalize_embeddings=True,
        convert_to_numpy=True,
    )
    return vector[0].tolist()


# ════════════════════════════════════════════════════════════
# 단계 ② : Qdrant 검색
# ════════════════════════════════════════════════════════════
def search_qdrant(
    client: QdrantClient,
    query_vector: list[float],
    top_k: int = TOP_K,
    severity_filter: str | None = None,
) -> list[dict]:
    """
    쿼리 벡터로 유사한 CVE를 Qdrant에서 검색.

    severity_filter: 'CRITICAL' | 'HIGH' | 'MEDIUM' | 'LOW' | None
      - None이면 전체 severity 대상으로 검색
      - 값이 있으면 해당 severity만 필터링 후 검색
    """
    query_filter = None
    if severity_filter:
        query_filter = Filter(
            must=[
                FieldCondition(
                    key="severity",
                    match=MatchValue(value=severity_filter.upper()),
                )
            ]
        )

    results = client.query_points(
        collection_name=COLLECTION_NAME,
        query=query_vector,
        query_filter=query_filter,
        limit=top_k,
        with_payload=True,
    ).points

    # payload를 dict 리스트로 정리
    return [
        {
            "score":            r.score,
            "cve_id":           r.payload.get("cve_id"),
            "severity":         r.payload.get("severity"),
            "base_score":       r.payload.get("base_score"),
            "attack_vector":    r.payload.get("attack_vector"),
            "cwe_id":           r.payload.get("cwe_id"),
            "affected_products": r.payload.get("affected_products", []),
            "cvss_vector":      r.payload.get("cvss_vector"),
            "description":      r.payload.get("description", ""),
        }
        for r in results
    ]


# ════════════════════════════════════════════════════════════
# 단계 ③ : 컨텍스트 구성
# ════════════════════════════════════════════════════════════
def build_context(cve_list: list[dict]) -> str:
    """
    검색된 CVE 리스트를 LLM이 읽기 좋은 구조화된 텍스트로 변환.

    각 CVE 항목을 번호와 함께 명확히 구분하여
    LLM이 각 취약점을 개별적으로 인식할 수 있도록 함.
    """
    if not cve_list:
        return "No relevant CVE data found."

    blocks = []
    for i, cve in enumerate(cve_list, 1):
        products = ", ".join(cve["affected_products"]) or "N/A"
        block = (
            f"[CVE #{i}]\n"
            f"  ID            : {cve['cve_id']}\n"
            f"  Severity      : {cve['severity']} (CVSS {cve['base_score']})\n"
            f"  Attack Vector : {cve['attack_vector']}\n"
            f"  CWE           : {cve['cwe_id']}\n"
            f"  CVSS Vector   : {cve['cvss_vector']}\n"
            f"  Products      : {products}\n"
            f"  Description   : {cve['description']}\n"
            f"  (Similarity   : {cve['score']:.4f})"
        )
        blocks.append(block)

    return "\n\n".join(blocks)


# ════════════════════════════════════════════════════════════
# 단계 ④ : 프롬프트 조립
# ════════════════════════════════════════════════════════════
def build_prompt(user_query: str, context: str) -> str:
    """
    페르소나(시스템) + 컨텍스트(검색 결과) + 질문을 하나의 프롬프트로 조립.

    구조:
      [SYSTEM PERSONA]   → LLM 역할 및 응답 규칙 정의
      [RETRIEVED CVEs]   → Qdrant에서 검색한 관련 CVE 데이터
      [USER QUESTION]    → 실제 사용자 질문
      [INSTRUCTIONS]     → 응답 형식 지시
    """
    prompt = f"""### SYSTEM PERSONA
{SYSTEM_PERSONA}

### RETRIEVED CVE DATA (from database)
The following CVEs were retrieved based on semantic similarity to the user's question.
Use this data as your primary source of information.

{context}

### USER QUESTION
{user_query}

### INSTRUCTIONS
Based on the retrieved CVE data above, provide a structured analysis.
Format your response as:
1. Brief summary of the vulnerability type
2. List each relevant CVE with: ID, severity, risk explanation
3. Recommended remediation steps
"""
    return prompt


# ════════════════════════════════════════════════════════════
# 단계 ⑤ : Gemma 호출 (Ollama REST API)
# ════════════════════════════════════════════════════════════
def call_llm(prompt: str, stream: bool = True) -> str:
    """
    Ollama REST API를 통해 Gemma2:2b 모델 호출.

    stream=True : 토큰이 생성되는 대로 실시간 출력 (응답 체감 속도 향상)
    stream=False: 전체 응답을 한 번에 반환
    """
    payload = {
        "model":  LLM_MODEL,
        "prompt": prompt,
        "stream": stream,
        "options": {
            "temperature": 0.3,    # 낮을수록 일관된 답변 (보안 분석에 적합)
            "top_p": 0.9,
            "num_predict": 1024,   # 최대 생성 토큰 수
        },
    }

    response = requests.post(OLLAMA_URL, json=payload, stream=stream, timeout=120)
    response.raise_for_status()

    if stream:
        # 스트리밍: 토큰 단위로 실시간 출력
        full_text = ""
        for line in response.iter_lines():
            if line:
                import json
                chunk = json.loads(line)
                token = chunk.get("response", "")
                print(token, end="", flush=True)
                full_text += token
                if chunk.get("done"):
                    print()  # 줄바꿈
                    break
        return full_text
    else:
        import json
        return response.json().get("response", "")


# ════════════════════════════════════════════════════════════
# 전체 파이프라인 실행
# ════════════════════════════════════════════════════════════
def run_rag(
    query: str,
    top_k: int = TOP_K,
    severity_filter: str | None = None,
    show_retrieved: bool = True,
) -> str:
    """
    RAG 전체 파이프라인 실행 함수.

    Args:
        query           : 사용자 자연어 질문
        top_k           : 검색할 CVE 수 (기본 5개)
        severity_filter : 특정 severity만 검색 (None이면 전체)
        show_retrieved  : 검색된 CVE 목록 출력 여부
    """
    print("=" * 60)
    print(f"질문: {query}")
    if severity_filter:
        print(f"필터: severity={severity_filter}")
    print("=" * 60)

    # 클라이언트 초기화 (매 호출마다 재사용 가능하도록 외부에서 주입 권장)
    embed_model = SentenceTransformer(EMBED_MODEL)
    qdrant_client = QdrantClient(url=QDRANT_URL)

    # ① 쿼리 임베딩
    print("\n[①] 쿼리 임베딩 중...")
    query_vector = embed_query(embed_model, query)
    print(f"    → 벡터 차원: {len(query_vector)}")

    # ② Qdrant 검색
    print(f"\n[②] Qdrant 검색 중 (top_k={top_k})...")
    cve_results = search_qdrant(qdrant_client, query_vector, top_k, severity_filter)
    print(f"    → 검색된 CVE: {len(cve_results)}개")

    if show_retrieved:
        print("\n    [검색 결과 미리보기]")
        for cve in cve_results:
            print(f"    {cve['cve_id']} | {cve['severity']:<8} | "
                  f"score {cve['base_score']} | 유사도 {cve['score']:.4f}")

    # ③ 컨텍스트 구성
    print("\n[③] 컨텍스트 구성 중...")
    context = build_context(cve_results)
    print(f"    → 컨텍스트 길이: {len(context)}자")

    # ④ 프롬프트 조립
    print("\n[④] 프롬프트 조립 중...")
    prompt = build_prompt(query, context)
    print(f"    → 프롬프트 길이: {len(prompt)}자")

    # ⑤ Gemma 호출
    print(f"\n[⑤] Gemma2:2b 응답 생성 중...\n")
    print("-" * 60)
    answer = call_llm(prompt, stream=True)
    print("-" * 60)

    return answer


# ── 실행 ───────────────────────────────────────────────────
if __name__ == "__main__":
    # 테스트 쿼리 1: 일반 취약점 검색
    run_rag(
        query="SQL injection vulnerabilities in web applications",
        top_k=5,
    )

    print("\n\n")

    # 테스트 쿼리 2: CRITICAL 심각도 필터 + 한국어 질문
    run_rag(
        query="원격 코드 실행이 가능한 심각한 취약점을 알려줘",
        top_k=5,
        severity_filter="CRITICAL",
    )
