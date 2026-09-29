# 현재 Java CPG + LLM 엔진

## 분석 방식

1. Spring 백엔드가 Java 파일을 Java 전용 분석 API로 보냅니다. `Java Spring Boot` 언어 표기도 이 경로에 포함됩니다.
2. Joern이 CPG를 만들고 고정 source/sink/sanitizer 규칙으로 데이터 흐름을 분석합니다.
3. Qwen3.8-Max가 제공된 Java 소스를 의미 분석합니다. 긴 파일은 겹치는 창으로 나누되 원본 줄 번호를 유지합니다.
4. CPG 경고와 high-confidence 의미 분석 경고를 병합하고 원본 파일·라인·출처·근거를 반환합니다.
5. 백엔드가 결과를 저장하고 프론트가 공격 시나리오와 수정 방법을 보여줍니다.

`shadow`에서는 새로 제안된 동적 규칙이 CPG 판정을 바꾸지 않습니다.
배포 Compose는 rulegen, critic, 동적 sanitizer/propagation을 모두 끕니다.
Qwen 의미 분석은 별도로 실행됩니다. 연구용 context 엔진이나 정답 CWE를 이용한 라우팅 실험은 이 배포 경로가 아닙니다.

## 코드 찾아보기

| 역할 | 파일 |
|---|---|
| API·결과 병합·요청 제한 | [api_rebuild.py](../scripts/api_rebuild.py) |
| CPG 오케스트레이션 | [graph_spec_prod.py](../scanops/core/graph_spec_prod.py) |
| Qwen 의미 분석 | [java_semantic.py](../scanops/core/java_semantic.py) |
| Joern 작업 처리 | [handler_joern.py](../joern/handler_joern.py) |
| 고정 규칙 | [java_base.tsv](../scanops/core/specs/java_base.tsv), [java_sanitizers.tsv](../scanops/core/specs/java_sanitizers.tsv) |
| Joern taint 쿼리 | [taint_spec.sc](../joern/queries/taint_spec.sc) |

## 실행

`scanops-model`, `scanops-infra`를 같은 부모 디렉터리에 clone하고 두 저장소의 `main`을 사용합니다.
[인프라의 현재 실행 안내](https://github.com/26Graduation/scanops-infra/blob/main/docs/JAVA_DEPLOYMENT.md)에 따라
`.env.java.example`을 복사하고 API 키·DashScope 주소·분석 호스트의 private IP를 채운 뒤 실행합니다.
Java 엔진은 외부 Qwen API를 사용하며, 로컬 QLoRA 가중치나 GPU는 요구하지 않습니다.

API: `GET /health`, `POST /analyze`, `POST /analyze/batch`, `POST /analyze/pr`.
분석 요청에는 `X-API-Key`가 필요합니다. batch 입력 예:

```json
{"files":[{"language":"Java","file_path":"Demo.java","code":"class Demo {}","use_rag":false}],"stop_on_first":false}
```

`/health`는 API 프로세스 확인입니다. Joern·Qwen의 실제 분석 성공은 별도입니다.
불완전 분석은 `PARTIAL`/실패로 처리하며 안전 판정으로 바꾸지 않습니다.

## 확인된 범위

2026-09-08 기록상 취약/안전 Java 2파일의 사이트 연동이 완료됐습니다.
복수 경고와 원본 라인 전달은 계약 테스트가 있고, 대규모 저장소의 지연·정확도는 검증되지 않았습니다.
창 사이·파일 사이 의미 추론에는 한계가 있습니다. [검증 안내](VERIFICATION.md)를 함께 읽어 주세요.
