# Joern CPG 하이브리드 — 야간 무인 세션 보고서

브랜치 `feat/joern-hybrid` (base `aadce1a`, 원 브랜치 `ablation/graph-only`)
작성 주체: 무인 에이전트 세션 (2026-08-16 03:10 KST 시작)

> 읽는 법: 모든 수치 옆에 출처(파일 §절 / 명령)를 달았다. **실측**과 **추정**을 구분해 적었고,
> 확인하지 못한 것은 "확인 불가"로 적었다. 실패·미완은 §9에, 아침에 사용자가 결정할 것은 §12에 모았다.

---

## §0 STATUS

**최종 갱신: 2026-08-16 03:40 KST**

| 항목 | 상태 |
|---|---|
| Phase 0 토폴로지 실측 | ✅ 완료 (§1) |
| Phase 1-A Joern 워커 | 🔄 코드 작성 완료, 로컬 검증 대기 (Joern 이미지 pull 중) |
| Phase 1-B logprob 서빙 | 🔄 코드 작성 완료, 검증 대기 |
| Phase 2 precision 게이트 | ⏳ 미착수 |
| Phase 3 하이브리드 | ⏳ 미착수 |
| Phase 4 온프레미스 compose | ⏳ 미착수 |
| Phase 6 마무리 | ⏳ 미착수 |

**RunPod 잔액**: $28.3982 (03:20 KST 실측). 이 세션 지출 상한 = min(28.40−5, 10) = **$10.00**.
현재까지 이 세션이 유발한 RunPod 지출: **$0** (GPU 호출 없음).

**진행 중 이슈**: Docker credential helper(`desktop`)가 무한 대기 → `docker pull` 불가.
빈 `DOCKER_CONFIG` 로 익명 pull 우회 확인(§9-1).

---

## §1 토폴로지 실측 (Phase 0)

추정 없이 파일에서 확인한 것만 적는다.

### 1-a. 백엔드 배포 (scanops-infra)

| compose 파일 | 용도 (헤더 주석 기준) |
|---|---|
| `docker-compose.yml` | 로컬 개발 전용: ZAP + DVWA + dvwa-db(mariadb) + postgres. 백엔드·모델 없음 |
| `docker-compose.aws.yml`:1-11 | AWS 프로덕션 올인원(EC2 1대): backend + model-server + ollama + qdrant + zap + postgres. **backend만 외부 노출** |
| `docker-compose.v17.yml`:1-14 | AWS/CPU 변형. ollama·qdrant 제거, model-server = `api_v17`(v13∨v16.1 앙상블), LLM은 RunPod. ZAP은 `zap-local` 프로파일 |
| `docker-compose.rebuild.yml`:1-14 | **현행**. model-server = `api_rebuild`(Qwen3.5-9B 단일), `Dockerfile.rebuild-api`, `RUNPOD_TIMEOUT` 기본 420 |

`docker-compose.aws.yml` 서비스별 실측:

| 서비스 | 이미지/빌드 | 포트 | 외부 지시 env |
|---|---|---|---|
| backend | `../scanops-backend/Dockerfile` (:15-43) | `8080:8080` | `JDBC_DATABASE_URL=jdbc:postgresql://postgres:5432/...`(:22), `SCANOPS_MODEL_URL=http://model-server:8100`(:26), `ZAP_HOST=http://zap:8090`(:28) |
| model-server | `../scanops-model/Dockerfile` (:46-61) | 없음(내부) | `PORT=8100`, `QDRANT_URL=http://qdrant:6333`(:52), `OLLAMA_URL=http://ollama:11434/api/generate`(:54) |
| ollama | `ollama/ollama:latest` (:64-70) | 없음 | — |
| qdrant | `qdrant/qdrant:latest` (:74-79) | 없음 | — |
| zap | `ghcr.io/zaproxy/zaproxy:stable` (:82-89) | 없음(의도적, :90) | — |
| postgres | `postgres:15` (:93-102) | 없음 | — |

`AWS_MIGRATION.md`:76-101 — 배포는 3블록으로 분리: **A 상시** backend+postgres+qdrant (t3.medium),
**B 온디맨드** model-server+ollama (g4dn.xlarge GPU), **C 온디맨드** zap (c5.large/Fargate).
:159 — backend 와 model-server 의 `SCANOPS_API_KEY` 는 동일해야 한다.

### 1-b. 분석 서버 `api_rebuild.py` 의 실제 실행 위치 — **사용자 진술과 다름**

사용자 진술은 "api_rebuild.py 가 RunPod 워커 안에 포함"이었으나, 파일 실측 결과는 다음과 같다.

| 구성요소 | 실제 위치 | 근거 |
|---|---|---|
| `scripts/api_rebuild.py` | **EC2 컨테이너(model-server)**. RunPod 워커 안이 아니다 | `docker-compose.rebuild.yml` 이 `model-server` 를 `Dockerfile.rebuild-api` 로 빌드하고 포트 8100 을 백엔드에 노출. `api_rebuild.py` 도커스트링 :17 "uvicorn scripts.api_rebuild:app --port 8100" |
| `runpod/handler_rebuild.py` | **RunPod serverless 워커 안** | `runpod.serverless.start()` (:93). llama-server 를 컨테이너 안에서 띄우고(:38-57) `/completion`·`/v1/chat/completions` 프록시 |
| 둘의 관계 | api_rebuild → `scanops/core/llm_client` → (RUNPOD_ENDPOINT_ID 설정 시) RunPod `runsync` → handler_rebuild → 로컬 llama-server | `llm_client.py`:39-50(completion), :72-99(_runpod_call), `api_rebuild.py`:41 |

즉 **api_rebuild 는 GPU를 직접 갖지 않는 얇은 오케스트레이터**이고, GPU 호출만 RunPod로 나간다.
`RUNPOD_ENDPOINT_ID` 미설정 시 로컬 `LLAMA_SERVER_URL`(기본 `http://localhost:8080`)로 폴백한다
(`llm_client.py`:30-36). — **이것이 Phase 4 온프레미스가 성립하는 근거다.**

### 1-c. 백엔드 → 분석서버 계약

`scanops-backend/.../ScanopsModelClient.java` — base URL 프로퍼티 `scanops.model.url`,
기본 `http://localhost:8100` (:26), `application.yml`:74-76 에서 `SCANOPS_MODEL_URL` 주입.

```java
public record AnalyzeRequest(String language, String code, String file_path, boolean use_rag) {}
public record CveReference(String cve_id, String severity, double base_score,
                            String cwe_id, String description) {}
public record AnalyzeResult(
        String language, String file_path,
        boolean detected, int stage,
        String vulnerability, String severity,
        Double cvss_score,
        String reason, String attack, String fix, String summary,
        List<CveReference> cve_references,
        double elapsed) {}
public record BatchRequest(List<AnalyzeRequest> files, boolean stop_on_first) {}
public record BatchResult(int total, int detected_count,
                           List<AnalyzeResult> results, double elapsed) {}
```

- `POST /analyze` 타임아웃 480s (:54-68), `POST /analyze/batch` 타임아웃 **30분** (:71-86), `GET /health` (:89-102).
- **`/analyze/pr` 은 ScanopsModelClient 에 없다.** `GitHubAppWebhookController.java`:167-192 에서
  타입 없는 `Map`/`JsonNode` 로 직접 호출한다(요청 키 `repo`/`pr_number`/`files[{filename,content,patch}]`,
  헤더 `X-Scanops-Key`). 응답은 `findings`/`vulnerable_count` 만 읽는다(:200-231).
  → **PR 경로에는 자바 DTO가 없어 필드를 추가해도 컴파일이 깨지지 않는다** (Phase 3에 유리).

**백엔드가 보내는 language 문자열 — 실측 (`GithubScanService.java`:51-68)**
사용자 진술(`"Java"`, `"TypeScript"`)과 **다르다**. 실제 값은 아래다.

| 확장자 | language 문자열 |
|---|---|
| `.java` | `Java Spring Boot` |
| `.kt` | `Kotlin` |
| `.jsx` / `.tsx` | `React / Next.js` |
| `.js` / **`.ts`** | `Node.js / Express` |
| `.py` | `Python` |
| `.go` | `Go` |
| `.rs` | `Rust` |
| `.c` / `.h` | `C` |
| `.cpp` | `C++` |
| `.php` | `PHP` |
| `.rb` | `Ruby` |
| `.yml` / `.yaml` | `GitHub Actions YAML` |

한편 `api_rebuild.py`:201-206 의 자체 `_EXT_LANG`(PR 경로에서 파일명→언어 추론용)은 **또 다르다**:
`.java`→`Java`, `.js`→`Node.js / Express`, `.ts`→`TypeScript`, `.c`→`C`.
→ Joern 확장자 매핑은 **두 소스의 합집합**을 키로 만들었다 (`joern/langmap.py`).
레포 파일 나열은 50개로 상한 (`GithubScanService.java`:130).

### 1-d. 백엔드에 콜백 엔드포인트 — **없음 (실측)**

컨트롤러 전수 조사 결과 외부 분석기가 결과를 POST 할 수 있는 엔드포인트가 없다.
- `POST /api/github/webhook` — GitHub App 웹훅 수신(HMAC 검증), 분석 결과 싱크 아님
- `POST /api/github/pr-scan` — GitHub Action 인바운드, 모델을 **동기 호출**만 함
- `GET /api/reports/{jobId}`, `POST /api/vulnerabilities/{id}/meta` — 조회/메타 갱신
- 모델 호출은 전부 블로킹 `WebClient...block()` (480s / 30min)

→ **Phase 1-A 의 비동기 설계는 "콜백"이 아니라 "폴링"이어야 한다.** 사양서가 제시한
콜백 URL POST 방식은 백엔드에 수신부가 없어 그대로는 성립하지 않는다. 워커는
`/joern/submit` + `/joern/result/{job_id}` 폴링 계약으로 구현했다(§2). 백엔드에 콜백 수신부를
만드는 것은 §12 결정사항으로 넘긴다.

### 1-e. RunPod 잔액·활성 endpoint (실측)

사용한 명령 (runpodctl 없음 → GraphQL 직접 호출):
```bash
curl -s -X POST "https://api.runpod.io/graphql?api_key=$RUNPOD_API_KEY" \
  -H "Content-Type: application/json" \
  -d '{"query":"query { myself { id clientBalance currentSpendPerHr endpoints { id name templateId workersMax workersStandby } pods { id name desiredStatus costPerHr } } }"}'
```
결과 (2026-08-16 03:20 KST):

| 항목 | 값 |
|---|---|
| clientBalance | **$28.3981636047** |
| currentSpendPerHr | $0.005 |
| pods | **[] (없음)** |
| endpoint 1 | `s43ugz0wqk5wtj` "scanops", template `cc7k8r5mo6`, workersMax 2, workersStandby 2 |
| endpoint 2 | `ylzf0yaerkvqli` "scanops-rebuild", template `nqwmt546b8`, workersMax 2, workersStandby 2 |

워커 상태 (`GET https://api.runpod.ai/v2/{id}/health`):
- `s43ugz0wqk5wtj`: idle 2 / ready 2 / running 0, 누적 completed 237 failed 4
- `ylzf0yaerkvqli`: idle 1 / initializing 1 / ready 1 / running 0, 누적 completed 166 failed 0

> **주의**: 두 endpoint 모두 `workersStandby=2` 다. 이는 이 세션이 만든 것이 아니라
> **기존 설정**이며, 세션 종료 시 0으로 되돌릴 대상이 아니다(사용자 프로덕션 설정 변경은 범위 밖).
> `currentSpendPerHr=$0.005` 로 실제 과금은 미미하다. §12에 확인 항목으로 남긴다.

### 1-f. 컨테이너 레지스트리 로그인 상태 — **push 불가 (실측)**

`~/.docker/config.json`: `credsStore="desktop"`, `auths` 키에 `https://index.docker.io/v1/` 존재
= **Docker Hub 로그인 이력은 있다.** 그러나 `docker-credential-desktop` 헬퍼가 **응답하지 않는다**:
```
$ docker pull hello-world
error getting credentials - err: signal: terminated, out: ``
```
(120초 타임아웃으로 강제 종료. 20분간 `docker pull ghcr.io/joernio/joern` 이 0바이트 진행이었던 원인.)

→ **결론: 이 세션에서 Docker Hub push 불가.** 빈 `DOCKER_CONFIG` 디렉토리를 쓰면 **익명 pull 은 정상**
(hello-world 로 확인). 따라서 이미지 빌드·로컬 실행은 가능하고, 레지스트리 push 와
RunPod endpoint 생성은 건너뛴다(폴백 규칙 §9). Phase 2 벤치는 예정대로 로컬 docker 로 돌린다.

### 1-g. 자체 graph 기준선 — Joern 이 넘어야 할 선

`rebuild/out/ABLATION_RESULTS.md` §0·§2-0·§3 에서 그대로 옮김 (재계산 없음):

| 지표 | 값 |
|---|---|
| 측정 대상 | CleanVul_v2 report split 중 graph 지원 언어 **1,878건** (Java 890 / Python 576 / JS 412) |
| graph=vuln | **20건** → gold vuln 12 / gold safe 8 → **precision 0.60**, recall 12/939 = **0.0128** |
| graph=safe | 137건 → gold safe 77 / **gold vuln 60** → false-safe **43.8%**. Java 는 113건 중 **48건(42.5%)이 실제 취약** |
| graph=unknown | **1,721건 = 91.6%** (Java 0.867 / Python 0.946 / JS 0.981) |
| 하이브리드 기여 | arm(a) LLM+graph vs arm(b) LLM만 → **ΔF1 = −0.0014, 95% CI [−0.0043, +0.0011] — 0 포함** |
| C/C++ | 828건 전량 graph 미지원 (`multi_graph._lang_key()` → None) |

**해석(원문 §0 그대로)**: arm(c) 의 낮은 recall 은 오탐 억제가 아니라 **판정 회피**에서 왔다.
graph 는 틀린 게 아니라 10건 중 9건에서 답을 하지 않았다.

### 1-h. 연속 점수(logprob) 서빙 지원 여부 — **없음 (실측)**

- `rebuild/score_logprob.py`:52-58 — `" NONE"`/`" CWE"` 의 **첫 토큰 ID**를 토크나이저에서 뽑아
  `score = logP(" CWE") − logP(" NONE")` 로 정의. 사양서가 준 기준값 41451 / 49149.
- `scanops/core/llm_client.py` (수정 전) — `completion()` 은 `n_predict`/`temperature`/`stop` 만 보낸다.
  **logprob 옵션 없음.**
- `runpod/handler_rebuild.py` (수정 전) — `/completion` 프록시에 `n_probs` 없음. **logprob 옵션 없음.**

→ Phase 1-B 에서 뚫었다(§3).

### 1-i. CleanVul_v2 언어별 라벨 수 (실측)

```bash
python3 -c "...collections.Counter((meta.language, meta.label))..."  # rebuild/data/cleanvul_v2_*.jsonl
```

| 언어 | report vuln | report safe | 계 |
|---|---|---|---|
| Java | 445 | 445 | 890 |
| Python | 288 | 288 | 576 |
| JavaScript | 206 | 206 | 412 |
| C | 407 | 407 | 814 |
| C++ | 7 | 7 | 14 |
| **합계** | **1,353** | **1,353** | **2,706** |

tune split = **676건** (vuln 338 / safe 338). 지원 언어(Java/Python/JS) 부분집합은 §2-①에서 산출.
→ **세 언어 모두 vuln ≥ 40** 이므로 Phase 2 의 층화 240건(언어별 40/40) 구성이 가능하다.

- `rebuild/out/v1_logprob_cleanvul_v2_tune.jsonl` **존재**(184,786 B), `..._report.jsonl` 존재(740,014 B).
- `rebuild/out/ablation_raw_cleanvul_v2_report.jsonl` = 2,706행. 각 행에 `case_id`(예 `cvh_0|vuln`),
  `lang`, `label`, **`llm_score`**, `graph_verdict`, `graph_supported` 가 이미 들어 있다.
  → Phase 2 는 **LLM 재추론 없이** 이 캐시된 점수를 쓴다 (R2 읽기 전용 준수, GPU 비용 $0).
- **case_id 에 `|` 가 들어 있다** → 파일명으로 쓸 수 없다. `joern/handler_joern.py` 가
  `[^A-Za-z0-9_.-]` 를 `_` 로 치환하고 역변환 표(`id_map`)를 결과에 함께 저장한다.

### 1-j. 로컬 실행 환경 (실측)

| 항목 | 값 |
|---|---|
| OS | macOS 26.5.1 (Darwin 25.5.0), arm64 |
| Docker | 데몬 최초 미기동 → `open -a Docker` 로 기동. 서버 **29.0.1** |
| 디스크 여유 | **51 GiB** (`/`, 460Gi 중 12Gi 사용 + 이미지 44.42GB) |
| RAM | **16 GiB** (`hw.memsize = 17179869184`) |
| 기존 이미지 | 11개 44.42GB (24.07GB 회수 가능), 실행 중 컨테이너 5개 (freqtrade/dvwa/zap 등 **사용자 것**) |

> RAM 16GB / 실행 중 컨테이너 5개 → Joern JVM 힙은 `-Xmx4g` 로 잡았다(§2).
> **사용자가 이미 돌리고 있는 컨테이너는 종료하지 않는다** (§8 결정 로그 D-3).

### 1-k. Joern 사실 확인

| 항목 | 값 | 출처 |
|---|---|---|
| 라이선스 | Apache License 2.0 | 확인 예정 — §9 참조 |
| 지원 언어 | 확인 예정 | |
| JVM 메모리 | 확인 예정 | |
| workspace API | 확인 예정 | |

---

## §2 Joern 워커 설계 (Phase 1-A)

작성 중.

## §3 logprob 서빙 검증 (Phase 1-B)

작성 중.

## §4 DELTA·TAU 선정 + precision 게이트 (Phase 2)

작성 중.

## §5 하이브리드 정책 (Phase 3)

작성 중.

## §6 온프레미스 (Phase 4)

작성 중.

## §7 병목과 해결책

작성 중.

## §8 결정 로그

| 시각 | 결정 | 대안 | 근거 | 되돌리는 법 |
|---|---|---|---|---|
| 03:12 | 브랜치를 `ablation/graph-only`(HEAD `aadce1a`)에서 분기 | `main` 에서 분기 | 벤치 입력인 `rebuild/data/cleanvul_v2_*.jsonl`, `rebuild/out/ablation_raw_*` 이 이 브랜치의 **미추적 파일**로만 존재 — main 에서 분기하면 Phase 2 입력이 없다 | `git checkout main` |
| 03:35 | Docker credential helper 우회를 위해 빈 `DOCKER_CONFIG` 사용 | `~/.docker/config.json` 수정 | 사용자 전역 설정을 건드리지 않는다 | 환경변수만 안 쓰면 원상복구 |
| 03:36 | 사용자가 실행 중인 컨테이너 5개는 건드리지 않는다 | 전부 정지 | 이 세션이 띄운 것이 아니고, 정지는 되돌리기 어려운 부작용 | 해당 없음 |

## §9 실패·미완·폴백 발동

**§9-1 Docker credential helper 무응답 (폴백 발동)**
`docker-credential-desktop` 이 응답하지 않아 인증이 필요한 모든 docker 작업이 무한 대기.
20분간 `docker pull` 이 0바이트 진행. 빈 `DOCKER_CONFIG` 로 익명 pull 우회.
**영향**: Docker Hub **push 불가** → RunPod endpoint 생성 생략 (사양서 2절 폴백 규칙대로
`joern/runpod_endpoint_payload.json` 만 작성). Phase 2 벤치는 로컬 docker 로 진행.

## §10 재현 명령어

작성 중.

## §11 아키텍처

작성 중.

## §12 아침에 결정할 것

작성 중.
