# ScanOps × Joern CPG 워커

Joern(Apache-2.0, <https://github.com/joernio/joern>)의 Code Property Graph 로 taint 흐름을
뽑아 파인튜닝 LLM 판정과 합치기 위한 워커. **서버리스(SaaS)** 와 **온프레미스** 양쪽에서
같은 코드가 돈다.

```
joern/
  Dockerfile                  베이스 ghcr.io/joernio/joern:master + python 런타임
  handler_joern.py            엔진 + 3진입점(RunPod / FastAPI / CLI 배치)
  langmap.py                  백엔드 language 문자열 → 확장자 · Joern frontend
  queries/taint.sc            CPG 쿼리 (multi_graph 11종 카테고리와 1:1)
  joern_docker.sh             호스트에서 joern 을 컨테이너로 실행하는 래퍼
  bench_joern.py              Phase 2 벤치 드라이버 (append·재개 가능)
  analyze_joern.py            DELTA·TAU 선정 + precision 게이트 판정
  runpod_endpoint_payload.json  RunPod 템플릿/엔드포인트 생성 페이로드
```

## 3가지 실행 형태

| 형태 | 기동 | 용도 |
|---|---|---|
| RunPod serverless | `RUNPOD_MODE=1 python3 -m joern.handler_joern` | SaaS. 이미지 기본 CMD |
| 온프레미스 HTTP | `uvicorn joern.handler_joern:app --port 8200` | 외부 호출 0. `docker-compose.onprem.yml` |
| 배치 CLI | `python3 -m joern.handler_joern --batch m.json --out r.json` | 벤치 평가 |

## 입출력 계약

요청:
```json
{"input": {"job_id": "scan_1", "language": "Java Spring Boot",
           "files": [{"path": "a/B.java", "content": "..."}]}}
```

응답 (`results[path]`):
```json
{"verdict": "vuln|safe|unknown",
 "unknown_reason": null,
 "categories": ["sqli"],
 "findings": [{"file": "a/B.java", "category": "sqli", "cwe": "CWE-89",
               "source": "...", "sink": "...", "line": 42, "path": ["..."]}],
 "wrap_level": 0, "elapsed": 1.2}
```
`unknown_reason` ∈ `unsupported_lang` | `parse_fail` | `timeout` | `id_unmapped`.
**결과 건수는 항상 입력 건수와 같다** — 누락은 unknown 으로 채운다.

## 설계상 중요한 결정

1. **격리** — 요청마다 `/tmp/scanops_{job_id}/` 를 새로 만든다. 이미 있으면 거부(중복 job_id).
   종료(성공·실패·타임아웃 모두) 시 `rm -rf` 하고 `CLEANUP` 로그를 남긴다. 워커 하나에 요청이
   여러 개 들어와도 서로의 디렉토리를 볼 수 없다.
2. **확장자 강제** — Joern 은 파일 확장자로 언어를 고른다. `langmap.ensure_ext()` 가 붙인다.
   매핑에 없는 language 는 파싱을 시도하지 않고 즉시 `unsupported_lang` 으로 돌려준다.
3. **래핑 재시도** — CleanVul 같은 함수 조각은 클래스/import 껍데기가 없어 파싱이 깨진다.
   1차 원문(`wrap_level=0`) → 실패분만 2차 최소 껍데기(`wrap_level=1`, Java `public class
   ScanopsSnippet { … }`, JS 함수 래핑, Python 은 좌측 정렬만) → 둘 다 실패면 `parse_fail`.
4. **배치 OOM 대책** — 케이스마다 JVM 을 띄우지 않는다. 청크(기본 25건)당 CPG 1개를 만들고
   청크가 끝나면 스크립트 안에서 `close`/`delete` 한다. 청크마다 peak RSS 를 기록해
   단조 증가하면 청크 크기를 줄이거나 JVM 을 재기동한다(실측 곡선은 보고서 §2).
5. **case_id 매핑** — `case_id` 에 파일명 금지 문자(`|` 등)가 있으면 `[^A-Za-z0-9_.-]` → `_`
   로 치환하고 충돌 시 `~N` 을 붙인다. 역변환 표를 `id_map` 으로 함께 돌려준다.
6. **비동기** — 백엔드에 콜백 수신 엔드포인트가 없다(보고서 §1-d 실측). 따라서 콜백 POST 가
   아니라 `POST /joern/submit` → `GET /joern/result/{job_id}` **폴링** 계약이다.
   LLM 결과와 Joern 결과는 서로 기다리지 않는다: LLM 먼저 반영(`status=PARTIAL`),
   Joern 도착 시 병합(`status=DONE`).

## 환경변수

| 변수 | 기본 | 뜻 |
|---|---|---|
| `JOERN_BIN` | `joern` | 실행 파일. 컨테이너 밖에서는 `joern/joern_docker.sh` 로 바꾼다 |
| `JOERN_SCRIPT` | `joern/queries/taint.sc` | 쿼리 스크립트 |
| `JOERN_WORK_ROOT` | `/tmp` | 작업 루트 |
| `JOERN_CHUNK` | `25` | 청크당 케이스 수 |
| `JOERN_CASE_TIMEOUT` | `90` | 케이스당 상한(초). 청크 타임아웃 = 이 값 × 청크 크기 |
| `JOERN_XMX` | `4g` | JVM 힙 상한 |
| `JOERN_HTTP` | (설정 시 on) | FastAPI 앱 구성 |
| `RUNPOD_MODE` | `1`(이미지) | serverless 진입 |
