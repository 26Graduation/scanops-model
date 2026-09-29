# AWS → RunPod Serverless 마이그레이션 가이드 (모델 서버)

> 대상: 현재 AWS g4dn(GPU) 위의 ScanOps 모델 API(`scripts/api_v15.py`, :8100/analyze).
> 결론: **도메인 불필요**, 백엔드 수정은 "URL + 인증헤더 + 응답 파싱" 3곳, 유휴 시 과금 0원.

## 1. 과금 구조 — 질문에 대한 답

- **맞음.** Serverless는 워커(컨테이너)가 **떠 있는 초 단위로만 과금**되고, 요청이 없으면
  워커 수 0으로 내려가 **0원**. 초당 단가는 GPU 티어별 고정.
- 2026년 기준 flex 워커 시간환산 단가: **16GB급 ~$0.58/hr, 24GB(L4/A5000급) ~$0.7–1.1/hr**
  (Pod 상시임대 대비 2~3배 단가지만, 유휴 0원이라 간헐 트래픽에선 압도적으로 쌈).
- 예상 비용 시뮬레이션 (V16 단일 모델, 요청당 추론 ~4초 + 오버헤드):
  | 월 요청 수 | 과금 시간 | 월 비용(16GB flex) |
  |---|---|---|
  | 1,000 | ~1.5h | **~$1** |
  | 10,000 | ~14h | **~$8** |
  | 100,000 | ~140h | ~$80 → 이 구간부턴 Pod 상시임대($0.2~0.4/hr)가 역전 |
- V15 앙상블(7B×2)은 요청당 시간이 ~2배 → 비용도 ~2배. **V16 증류가 서빙 비용 절반**의 의미.
- 숨은 비용: 컨테이너 레지스트리/네트워크 볼륨(수 GB, $0.07/GB/월 수준), cold start 동안의
  워커 기동 시간도 과금됨(아래 4번으로 최소화).

## 2. HTTPS / 도메인 — 질문에 대한 답

- **도메인 필요 없음.** RunPod이 엔드포인트를 만들어주면 주소가
  `https://api.runpod.ai/v2/<ENDPOINT_ID>/runsync` 형태로 **TLS(HTTPS)가 이미 붙어** 나옴.
- 인증은 `Authorization: Bearer <RUNPOD_API_KEY>` 헤더. 인증서 발급/갱신/nginx 전부 불필요.
- 지금까지는 VPC 내부 HTTP였지만, 이제 **백엔드(AWS/어디든) → 공인 HTTPS 엔드포인트** 호출로
  바뀌는 것뿐. 코드에 API 키만 환경변수로 주입하면 됨 (키를 레포에 커밋 금지).

## 3. 아키텍처 변경

```
[현재]  Spring AiRouter ──HTTP(사설IP)──> EC2 g4dn : api_v15(:8100) + Ollama + Qdrant
[이후]  Spring AiRouter ──HTTPS+API키──> RunPod Serverless(엔드포인트)
                                          └ Docker 이미지: Ollama + v16 어댑터 + handler.py
        (Qdrant는 RAG 메인흐름 밖 → 필요 시 Qdrant Cloud 무료티어 1GB로 분리)
```

RunPod Serverless는 "FastAPI 서버"가 아니라 **handler 함수** 방식:

```python
# handler.py (이미지 안에 포함)
import runpod, subprocess, time, requests

subprocess.Popen(["ollama", "serve"])           # 컨테이너 기동 시 1회
time.sleep(3)

def handler(job):
    inp = job["input"]                          # {"code": ..., "language": ...}
    r = requests.post("http://127.0.0.1:11434/api/chat", json={
        "model": "qwen2.5-coder-security-v16-7b",
        "messages": [{"role": "user", "content": build_prompt(inp)}],
        "stream": False,
        "options": {"temperature": 0, "num_predict": 256, "repeat_penalty": 1.3},
    }, timeout=120).json()
    return parse_3line(r["message"]["content"]) # {vulnerable, vulnerability, severity, cvss}

runpod.serverless.start({"handler": handler})
```

Dockerfile 핵심: `FROM ollama/ollama` 베이스 + `ollama pull qwen2.5-coder:7b-instruct`를
빌드 타임에 실행해 **베이스 가중치(4.5GB)를 이미지에 굽고**, `v16_7b_lora.gguf`+Modelfile로
`ollama create`까지 빌드 타임에 끝냄 → cold start에서 다운로드 0.

## 4. 마이그레이션 작업 체크리스트

1. **이미지 빌드·푸시** — Dockerfile(Ollama+어댑터+handler) 작성, Docker Hub/GHCR에 push.
   (기존 `deploy_v15/`의 Modelfile·어댑터 재활용, V16 완성 전엔 v13 단일로 먼저 검증 가능)
2. **RunPod 엔드포인트 생성** — GPU 16GB(V16 단일) 또는 24GB(V15 앙상블), min workers 0,
   max 1~2, **FlashBoot 켜기**(cold start 수 초~수십 초 → 최소화), idle timeout 5s.
3. **백엔드(AiRouter) 수정 — 3곳**:
   - URL: `http://<사설IP>:8100/analyze` → `https://api.runpod.ai/v2/<ID>/runsync`
   - 헤더: `Authorization: Bearer ${RUNPOD_API_KEY}` 추가
   - 요청/응답 래핑: 요청 body를 `{"input": {...기존 payload...}}`로, 응답은
     `{"status":"COMPLETED","output":{...기존 응답...}}`에서 `output` 꺼내기
4. **타임아웃 정책** — cold start 시 첫 요청이 30~90초 걸릴 수 있음.
   - 백엔드 HTTP 타임아웃 120s로 상향, 또는 `/run`(비동기)+폴링으로 전환
   - 데모/발표 직전엔 "워밍 요청" 1회 쏘거나 active worker 1개 잠깐 켜두기(시간당 과금)
5. **시크릿 관리** — RUNPOD_API_KEY를 백엔드 환경변수/시크릿으로. 레포 커밋 금지.
6. **Qdrant 분리(선택)** — RAG 데모가 필요하면 Qdrant Cloud 무료티어(1GB, 8,883개 충분)로
   옮기고 `QDRANT_URL` 환경변수만 교체. 판별 메인흐름엔 RAG 미사용이라 없어도 API 동작.
7. **검증** — `curl -X POST .../runsync -H "Authorization: Bearer ..." -d '{"input":{"code":"...","language":"Python"}}'`
   로 3줄 판정 확인 → 백엔드 통합 테스트 → 프론트 E2E.
8. **AWS 정리** — g4dn 인스턴스 중지→며칠 관찰→종료. EIP/EBS 잔여 과금 확인(스냅샷만 남기기).

## 5. 주의사항

- **cold start가 UX에 보임**: 사용자가 몇 시간 만에 첫 스캔을 누르면 30초+ 대기 가능.
  스캔은 원래 "몇 초~몇십 초 걸리는 작업"이라는 UI(진행 스피너)면 자연스럽게 흡수됨.
- flex 워커는 초당 단가가 지역/재고에 따라 바뀜 — 엔드포인트 생성 화면에서 실단가 확인.
- 요청량이 월 5만+ 로 꾸준해지면 Pod 상시임대(Community 4090 ~$0.3/hr)나 Vast.ai로 재평가.
