# 검증 범위

## 배포 기록 (2026-09-08)

- Java 전용 API, 백엔드 라우팅, 소규모 사이트 연동이 완료됐습니다.
- Java 파일 2개 중 취약 파일의 CWE-79 원본 12행 경고가 사이트에 표시됐고 안전 파일에는 경고가 없었습니다.
- 기존 비Java 모델은 health 및 빈 입력 계약만 확인했습니다. 정상 비Java 추론 전체를 재실행한 결과는 아닙니다.
- 상세한 당시 기록은 [인프라 보존 문서](https://github.com/26Graduation/scanops-infra/blob/main/JAVA_CPG_DEPLOYMENT_20260908.md)에 있습니다. 그 문서의 과거 실행 명령 대신 현재 README의 실행 안내를 사용합니다.

## 로컬 회귀 테스트

저장소 루트에서 Python 가상환경을 만들고 필요한 API 의존성을 설치한 뒤:

```sh
python -m pip install pytest fastapi httpx requests 'uvicorn[standard]' 'tree-sitter-language-pack==1.12.2'
python -m pytest -q tests/test_graph_spec_prod_java.py tests/test_java_cpg_primary_api.py tests/test_java_deployment_guards.py tests/test_joern_repo_worker.py tests/test_java_semantic.py tests/test_java_resource_context.py
```

이 테스트는 모의 응답을 사용하며, 유료 Qwen/RunPod 호출이나 실제 Joern 서버의 정확도를 측정하지 않습니다.
백엔드는 `./gradlew test`로 Java 라우팅 및 모델 응답 계약을 확인할 수 있습니다.

## 해석 제한

소규모 시연 성공과 테스트 통과는 정확도·재현율·성능 우위를 의미하지 않습니다.
`rebuild/out/`과 과거 발표 자료의 결과는 데이터, 입력 정보, 정책, 버전이 다를 수 있습니다.
정답 CWE를 사용하는 라우팅 실험 수치를 현재 blind 앙상블의 성능으로 인용하지 않습니다.
큰 저장소의 전체 종료시한·취소 전달·운영 부하 및 실제 PR 완료 경로에는 추가 검증이 필요합니다.

## main 통합 검증 (2026-09-14)

- 위 Python 회귀 테스트: 58 passed, 5 subtests passed.
- 최신 백엔드 main과 Java 작업 통합 후 Gradle 테스트: 40 tests, 0 failures, 0 errors.
- Java Docker Compose: 가상 검증값으로 `config --quiet` 통과. 컨테이너 기동·서버 재배포는 하지 않았습니다.
- 모델 베이스와 GGUF 어댑터의 로컬 SHA-256이 `models/MODELS.sha256`과 일치합니다.
- 새 README·안내 문서의 로컬 파일 링크를 확인했습니다.
- 유료 Qwen/RunPod 호출, 모델 재학습, 가중치 로드 추론은 실행하지 않았습니다.
