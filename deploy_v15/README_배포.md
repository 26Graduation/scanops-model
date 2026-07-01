# ScanOps V15 (앙상블) — 배포 안내 (인프라 담당)

V15 = **v13 ∨ v14 OR 앙상블.** 두 모델 + 코드그래프를 OR로 결합해(하나라도 취약이라 하면 취약)
재현율·정확도를 둘 다 높인 버전. **3벤치 평균 전 지표에서 상용 Grok 능가.** 학습·변환 끝났고,
아래 파일만 서버에 올리면 됩니다.

## 구성 (2부분)
1. **모델 서빙 (Ollama)** — v13·v14 어댑터를 Ollama에 등록.
2. **앙상블 API (FastAPI)** — 두 모델을 병렬 호출 + 그래프 결합해 단일 엔드포인트 제공.
   백엔드(Spring AiRouter의 `CUSTOM`)는 이 API 하나만 호출.

## 폴더 내용 (`deploy_v15/`)
| 파일 | 크기 | 설명 |
|---|---|---|
| `v13_7b_lora.gguf` | 39MB | v13 어댑터(고재현율) |
| `v14_7b_lora.gguf` | 308MB | v14 어댑터(고정밀, r64+MLP라 큼) |
| `Modelfile.v13` / `Modelfile.v14` | — | Ollama 등록 설정 |
| `setup.sh` | — | 베이스 pull + 두 모델 등록 자동화 |

## 전제조건
- **Ollama** 설치, 디스크 ~5.5GB(베이스 4.7GB + 어댑터 2개), RAM **~11GB 권장**(7B 두 개 동시 로드).
  RAM 부족 시 Ollama가 번갈아 로드(느려지지만 동작).

---

## 방법 A — 직접 실행 (간단)
```bash
# 1) 모델 등록 (이 폴더에서)
cd deploy_v15 && ./setup.sh
#    → qwen2.5-coder-security-v13-7b, -v14-7b 두 개 등록됨

# 2) 앙상블 API 실행 (레포 루트에서)
cd ..
pip install fastapi "uvicorn[standard]" pydantic requests httpx sentence-transformers qdrant-client
uvicorn scripts.api_v15:app --host 0.0.0.0 --port 8100
```

## 방법 B — Docker Compose
```bash
# 레포 루트에서
docker compose -f docker-compose.v15.yml up -d        # ollama + v15-api (+qdrant)
# 최초 1회 모델 등록 (ollama 컨테이너 안에서)
docker exec -it ollama sh -c "cd /models && ollama pull qwen2.5-coder:7b-instruct \
  && ollama create qwen2.5-coder-security-v13-7b -f Modelfile.v13 \
  && ollama create qwen2.5-coder-security-v14-7b -f Modelfile.v14"
```

---

## 동작 확인
```bash
curl http://localhost:8100/health
# → {"status":"ok","version":"15.0.0","ensemble":{...,"rule":"v13 OR v14 OR graph"}}

curl -X POST http://localhost:8100/analyze -H "Content-Type: application/json" -d '{
  "code":"q=\"SELECT * FROM u WHERE id=\"+request.args.get(\"id\")\ncur.execute(q)",
  "language":"Python"}'
# → {"vulnerable":true,"vulnerability":"...SQL/Code Injection...","severity":"HIGH",
#     "cvss":"8.1","source":"v13","votes":{"v13":true,"v14":true,"graph":false}, ...}
```

## 백엔드 연동 (Spring AiRouter)
- `CUSTOM` 엔진이 호출할 URL: `http://<서버>:8100/analyze` (POST, `{code, language}`).
- 응답의 `vulnerable`(bool) + `vulnerability`/`severity`/`cvss`로 리포트 구성.
- `votes`(v13/v14/graph)는 근거 표시·디버깅용.

## 환경변수 (선택)
| 변수 | 기본값 | 용도 |
|---|---|---|
| `SCANOPS_V13_MODEL` | qwen2.5-coder-security-v13-7b:latest | v13 모델명 |
| `SCANOPS_V14_MODEL` | qwen2.5-coder-security-v14-7b:latest | v14 모델명 |
| `OLLAMA_URL` | http://localhost:11434 | Ollama 주소 |
| `SCANOPS_API_KEY` | (없음) | 설정 시 `X-API-Key` 헤더 필수 |

## 성능 참고
- 요청당 ~6~8초(두 7B 모델 병렬 호출). RAM 여유 없으면 순차 로드로 더 걸림.
- CPU 서빙 가능(GPU 불필요). 처리량 필요하면 Ollama 인스턴스/복제 늘리면 됨.
- 재배포/롤백: 어댑터 `.gguf`만 교체 후 `ollama create` 재실행.
