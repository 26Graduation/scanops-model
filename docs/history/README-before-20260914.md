# ScanOps Model — 보안 특화 LLM + RAG 취약점 분석 도구

소스코드/코드 스니펫을 입력받아 CVE·CWE 기반 취약점 탐지, CVSS 점수, 수정 가이드를 제공하는 "보안 특화 Cursor".

---

## 아키텍처

```
입력 (코드 or 텍스트)
  ↓
임베딩 (BAAI/bge-small-en-v1.5)
  ↓
Qdrant 유사도 검색 (top-k CVE/CWE 컨텍스트)
  ↓
프롬프트 조립 (retrieved context + 입력 + 페르소나)
  ↓
파인튜닝 모델 (Ollama 서빙)
  ↓
출력: 취약점 목록 + CVE/CWE + CVSS + 수정 코드 스니펫
```

---

## 빠른 시작

### 1. 의존성 설치

```bash
pip install -e .
# 파인튜닝도 할 경우:
pip install -e ".[train]"
```

### 2. Qdrant 실행

```bash
docker-compose up -d
```

### 3. CVE 데이터 적재

```bash
# 기본 792개 (feat/sehan 전처리 데이터)
scanops db-prepare data/nvdcve-2.0-preprocessed.json

# 더 큰 데이터셋 (원본 NVD 피드 전처리 포함)
scanops db-prepare data/nvdcve-2.0-recent.json --raw --recreate
```

### 4. Ollama 모델 pull

```bash
brew services start ollama
ollama pull qwen2.5-coder:1.5b   # Railway 배포 권장 (≈1GB)
ollama pull gemma2:2b             # 로컬 고성능용
```

### 5. 환경변수 설정

```bash
cp .env.example .env
# .env 편집 후 필요시 QDRANT_URL, OLLAMA_MODEL 등 수정
```

---

## 사용법

### 파일 스캔

```bash
scanops scan ./src/login.py
scanops scan ./src/              # 디렉터리 재귀 스캔
```

### 코드 스니펫 직접 입력

```bash
scanops scan --code 'cursor.execute("SELECT * FROM users WHERE id=" + user_id)' --lang Python
```

### 대화형 CVE 검색

```bash
scanops chat
```

### 모델 벤치마크

```bash
scanops benchmark
scanops benchmark --base gemma2:2b --qwen qwen2.5-coder:1.5b
```

### JSON 결과 저장

```bash
scanops scan ./src/ --output ./reports/
```

---

## 파인튜닝

```bash
# Qwen2.5-Coder-1.5B QLoRA (기본값, Railway 배포용)
python -m scanops.models.train_qlora

# Gemma-2 2B LoRA (로컬 고성능)
python -m scanops.models.train_qlora --model gemma

# 학습 후 벤치마크 비교
scanops benchmark
```

학습 데이터: `data/lora_train_v2.jsonl` (203개, 19가지 CWE 커버)

---

## 데이터 선택 근거

| 항목 | feat/sehan | feat/hyeeun | 채택 |
|------|-----------|------------|------|
| 파인튜닝 데이터 | 203개, 19 CWE | 없음 | **sehan** |
| 벡터 DB 크기 | 792개 (ChromaDB) | 12,251개 (Qdrant) | **hyeeun 규모 목표** |
| 벡터 DB 엔진 | ChromaDB | Qdrant | **Qdrant** (검색 품질, 운영 편의) |
| RAG 아키텍처 | 2-stage | 1-stage | **1-stage** (안정적, 파인튜닝 모델과 결합) |

> 기본 제공 792개 데이터로 즉시 사용 가능. 더 큰 커버리지가 필요하면 NVD 공식 피드(`nvdcve-2.0-recent.json`)를 `--raw` 옵션으로 처리.

---

## 모델 선정 근거

| 모델 | Q4 메모리 | Railway | 탐지 품질 | 채택 |
|------|----------|---------|---------|------|
| Qwen2.5-Coder-1.5B | ~1GB | ✓ | 우수 (코드 특화) | **배포 기본값** |
| Gemma-2 2B | ~1.5GB | 한계 | 우수 | 로컬 비교용 |

> `OLLAMA_MODEL=qwen2.5-coder:1.5b` 환경변수로 변경 가능.

---

## 프로젝트 구조

```
scanops-model/
├── scanops/
│   ├── core/
│   │   ├── scanner.py      # 핵심 스캔 로직 (웹 백엔드 연동 가능)
│   │   ├── rag.py          # RAG 파이프라인 (Qdrant + Ollama)
│   │   └── embedder.py     # 임베딩 모듈 (BGE 싱글톤)
│   ├── models/
│   │   ├── train_qlora.py  # QLoRA 파인튜닝 (Qwen / Gemma-2)
│   │   └── benchmark.py    # 모델 벤치마크 비교
│   ├── data/
│   │   └── prepare.py      # NVD 전처리 + Qdrant 적재
│   └── cli.py              # CLI 진입점
├── data/
│   ├── nvdcve-2.0-preprocessed.json  # 792개 전처리 데이터 (기본)
│   └── lora_train_v2.jsonl           # 203개 파인튜닝 데이터
├── models/
│   └── gemma2-security-lora/         # 기존 Gemma-2 LoRA 어댑터
├── pyproject.toml
├── requirements.txt
├── docker-compose.yml
└── .env.example
```

---

## Railway 배포

```bash
# Qdrant: Railway 서비스로 분리 배포 후 환경변수 지정
QDRANT_URL=https://your-qdrant.railway.app
OLLAMA_URL=https://your-ollama.railway.app/api/generate
OLLAMA_MODEL=qwen2.5-coder:1.5b
```

Railway는 GPU 미지원이므로 Ollama CPU 추론 기준. Qwen2.5-Coder-1.5B Q4가 1GB RAM 내에서 동작.

---

## 백엔드 연동 (Spring Boot AiRouter)

`scanops.core.scanner`의 `scan_code()`, `scan_file()`은 CLI와 독립된 순수 함수.
FastAPI 엔드포인트 예시:

```python
from fastapi import FastAPI
from scanops.core.scanner import scan_code

app = FastAPI()

@app.post("/analyze")
def analyze(code: str, language: str = "Unknown"):
    result = scan_code(code, language=language)
    return result.to_dict()
```
