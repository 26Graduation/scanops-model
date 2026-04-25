# scanops-model

ScanOps Phase 3: 자체 Fine-tuned 보안 분석 모델

## 로드맵

### Phase 1 (현재) — GPT-4o 연동
백엔드 `GptAnalyzer`에서 OpenAI API 호출

### Phase 2 — Claude / Gemini 연동
`ClaudeAnalyzer`, `GeminiAnalyzer` 순서로 fallback 추가

### Phase 3 (이 레포) — Fine-tuned LLM
1. **데이터 수집**: NVD(National Vulnerability Database) CVE 데이터 + ZAP 스캔 결과
2. **전처리**: 취약점 유형별 레이블링, CVSS 벡터 파싱
3. **Fine-tuning**: Llama3 또는 Mistral 기반 LoRA 학습
4. **서빙**: FastAPI로 `/analyze` 엔드포인트 제공
5. **연동**: 백엔드 `AiRouter`에서 `CUSTOM` 모델로 라우팅

## 디렉토리 구조

```
data/        ← NVD 수집 데이터 (JSON, JSONL)
notebooks/   ← 학습 Colab 노트북
src/         ← 모델 서빙 코드
api/         ← FastAPI 서빙 엔드포인트 (추후)
```

## 참고 데이터셋

- [NVD JSON Feeds](https://nvd.nist.gov/vuln/data-feeds)
- [CVE Dataset on HuggingFace](https://huggingface.co/datasets?search=cve)
