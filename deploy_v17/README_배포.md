# ScanOps V17 배포 안내 (v13 ∨ v16.1 앙상블 + RunPod Serverless)

V17 = **v13(고재현율) ∨ v16.1(광커버리지) ∨ 코드그래프**.
4벤치 평균 F1 62.1 / 재현율 66.5% — V15(59.9)·Grok(56.2) 능가 (`reports/V16_RESULTS.md`).

## 아키텍처 (GPU 비용 절감형)

```
[Java 백엔드] ──HTTP──> [api_v17 (FastAPI, CPU면 충분)] ──┬─ RUNPOD_ENDPOINT_ID 설정 시
   (무변경)              /analyze /analyze/batch          │   → RunPod Serverless (HTTPS+키)
                         /analyze/pr /health              └─ 미설정 시 → 로컬 Ollama
```

- **Java 백엔드는 코드 변경 0** — REST 계약이 api_server.py와 동일.
- GPU가 필요한 건 LLM 호출뿐 → RunPod로 빼면 **EC2를 GPU(g4dn) → CPU(t3.large)로 다운그레이드** 가능.
- RunPod는 요청 없을 때 0원(초 단위 과금). 도메인/인증서 불필요(api.runpod.ai HTTPS + Bearer 키).

## A. 모델 API 서버 (api_v17)

```bash
pip install fastapi "uvicorn[standard]" pydantic requests
# RunPod 모드 (권장):
export RUNPOD_ENDPOINT_ID=<엔드포인트ID>
export RUNPOD_API_KEY=<런팟 API 키>
# (로컬 Ollama 모드면 위 두 줄 생략하고 ./setup.sh 로 모델 등록)
uvicorn scripts.api_v17:app --host 0.0.0.0 --port 8100
```

## B. RunPod Serverless 워커 (GPU)

1. 이미지 빌드·푸시 (레포 루트, Docker 필요, 이미지 ~11GB):
   ```bash
   docker build --platform linux/amd64 -t <dockerhub유저>/scanops-v17-worker:latest -f runpod/Dockerfile .
   docker push <dockerhub유저>/scanops-v17-worker:latest
   ```
2. RunPod 콘솔 → Serverless → New Endpoint:
   - Container Image: `<dockerhub유저>/scanops-v17-worker:latest`
   - GPU: **16GB (A4000/A4500급)** — 7B Q4 두 개 순차/동시 로드 OK
   - Workers: min 0 / max 2, Idle Timeout 5s, **FlashBoot ON**
   - Container Disk: 20GB
3. 생성된 Endpoint ID + API 키를 api_v17 환경변수에 넣기.
4. 검증:
   ```bash
   curl -X POST https://api.runpod.ai/v2/<ID>/runsync \
     -H "Authorization: Bearer <KEY>" -H "Content-Type: application/json" \
     -d '{"input":{"model":"qwen2.5-coder-security-v13-7b","messages":[{"role":"user","content":"Analyze this Python code for security vulnerabilities:\n\n```python\nos.system(cmd)\n```"}],"options":{"temperature":0,"num_predict":200}}}'
   ```

## C. 백엔드 연동 (변경 없음 확인만)

- `SCANOPS_MODEL_URL` = api_v17 주소 (기존과 동일 :8100)
- `SCANOPS_API_KEY` = 기존 그대로 (api_v17도 X-API-Key 지원)

## 폴더 내용

| 파일 | 설명 |
|---|---|
| `v13_7b_lora.gguf` (39MB) | v13 어댑터 (고재현율 멤버) |
| `v16_1_7b_lora.gguf` (308MB) | v16.1 어댑터 (광커버리지 멤버) |
| `Modelfile.v13` / `Modelfile.v16_1` | Ollama 등록 설정 |
| `setup.sh` | 로컬 Ollama 모드용 모델 등록 |

## 부가 기능 (환경변수)

| 변수 | 기본 | 설명 |
|---|---|---|
| `SCANOPS_META` | `on` | 탐지 시 한국어 메타 생성(summary 한줄요약·attack·fix). `off`로 비활성 |
| `SCANOPS_META_MODEL` | `qwen2.5-coder:7b-instruct` | 메타 생성용 모델(워커에 베이크됨) |
| `QDRANT_URL` | (없음) | 설정 시 응답에 참고 CVE 3건 부착(`cve_references`, 2026 NVD 8,883건 인덱스). **판정에는 미관여** |

- 모든 탐지 응답에 `ai_prompt`(외부 AI 핸드오프 프롬프트)와 `summary`(한줄 정리)가 포함됨 —
  DAST의 generateMeta와 대칭 구조. 프론트는 이 필드를 그대로 표시/복사버튼 처리하면 됨.
- 메타 생성은 탐지된 건에만 +1 LLM 콜(안전 판정은 추가 비용 0).

## 주의

- cold start: 유휴 후 첫 요청 30~90초 (FlashBoot로 단축). 백엔드 WebClient 타임아웃 120s 권장.
- 파일 많은 배치/PR 스캔은 파일당 LLM 2콜 → RunPod 워커가 순차 처리. max workers 2로 병렬화 가능.
- V15로 롤백: api_v17 대신 api_v15 실행 또는 `SCANOPS_V14_MODEL=qwen2.5-coder-security-v14-7b:latest`.
