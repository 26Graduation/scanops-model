# Java CPG + Qwen3.8-Max 완료 평가 사전등록

작성일: 2026-09-05  
대상 브랜치: `codex/java-cpg-qwen38`

## 1. 목표와 완료 조건

Java 레포에 대해 Qwen3.8-Max가 CPG source/sink/sanitizer 스펙을 생성하고 Joern이 실제
source→sink 경로를 탐색하는 제품 경로를 완성한다. 최종 원격 push는 아래 게이트를 모두
통과한 경우에만 수행한다.

- 동일한 held-out Java 평가셋에서 ScanOps의 취약점 인스턴스 F1과 recall이 사전 선정한
  최강 오픈웨이트 비교 모델보다 각각 5%p 이상 낮지 않을 것.
- ScanOps가 반환한 진탐에는 sink line이 있고, taint형 진탐에는 source→sink path가 있을 것.
- 파일 단위 경보를 대량으로 내서 recall만 높이는 결과는 통과로 보지 않는다.
- 룰 생성/Joern 배치 유실률 0%, 파싱 실패는 전부 수치와 원문을 보존할 것.
- 기존 JS/TS 회귀 테스트가 통과할 것.

## 2. 고정 모델과 비교 조건

- ScanOps CPG 룰 생성과 critic: DashScope `qwen3.8-max`, temperature 0.
- Java 최종 판정에는 CVEfixes Qwen3.5-9B QLoRA를 사용하지 않는다. G3 외부 저장소
  fail-fast에서 binary F1 0.444, 음성 파일 오탐 8/9로 전이 실패가 확인됐기 때문이다.
- Qwen3.5-9B QLoRA 결과는 실패한 과거 baseline으로만 보존한다.
- 오픈웨이트 비교 모델은 같은 파일/프롬프트/출력 스키마/토큰 예산으로 수행한다.
- 모델의 정확한 API ID와 호출일은 결과 보고서에 기록한다.
- API 키가 없는 비교 모델은 결과를 추정하거나 대체하지 않고 `BLOCKED_NO_KEY`로 기록한다.

## 3. 데이터 분리

1. **룰 생성 골든셋**: `benchmarks/golden-sets/java/rule_golden_set_v1.json`에
   `rule_golden_set_v2_overrides.json`을 적용한 41개 감사 뷰. 코퍼스의 dataflow 관습과
   재사용 가능한 API 의미가 충돌하는 항목은 실제 소스와 위협 모델을 대조해 v2에 기록한다.
   이 데이터는 룰 생성 단계 평가에만 쓴다.
2. **개발/회귀**: Juliet Java Tier A+B 38개 CWE. 엔진 기능과 회귀 확인용이며 최종 외부
   성능 주장에는 쓰지 않는다.
3. **최종 held-out**: CWE-Bench-Java 또는 동등한 실제 Java 프로젝트 기반 벤치. 결과를 본 뒤
   룰을 조정한 프로젝트는 이후 held-out에서 제외한다.

## 4. 채점 단위

### 주지표

`(repository, file, enclosing method, CWE)` 취약점 인스턴스 단위 precision/recall/F1.
같은 취약 메서드의 여러 정당한 sink 경보는 하나의 취약점 인스턴스로 합친다.

F1을 주지표로 둔 이유는 recall만 최적화하면 모든 파일에 경보를 내는 엔진도 좋아 보이고,
precision만 최적화하면 거의 아무것도 탐지하지 않는 엔진도 좋아 보이기 때문이다. F1은 두 값의
조화평균이라 한쪽이 낮으면 함께 낮아진다. 단, 보안 탐지에서 놓침의 비용이 더 크므로 recall을
독립 합격 게이트로 함께 두며, 경보 수/프로젝트와 parse failure도 반드시 별도 보고한다.

### 보조지표

- raw line alert TP/FP/FN 및 중복률
- F2 (놓침을 precision보다 두 배 가중)와 프로젝트/CVE 탐지율
- 같은 CVE의 buggy/fixed 쌍에서 fix 후에도 남는 목표-CWE 경보율
- CWE 엄격 일치와 CWE를 무시한 loose 적중
- source→sink path 존재율과 cross-file path 수
- CPG 생성 성공률, LLM JSON 파싱 성공률, API 호출 수/토큰/시간

Juliet FLAW 마커 주변의 모든 sink를 새 GT로 확장하지 않는다. 평가 룰이 탐지 룰에서 파생되는
순환 평가를 피하기 위해, 기존 라인 GT는 보존하고 취약점 인스턴스 중복만 별도 집계한다.

## 5. 단계별 게이트

### G0 — 제품 배선

- Java가 `JAVASRC`와 `Java` 프롬프트로 라우팅됨.
- JS/TS 손 룰이 Java 스펙에 포함되지 않음.
- Java 고정 기본 스펙과 sanitizer가 Joern 워커까지 전달됨.
- 캐시가 frontend별로 격리됨.
- 다대다 카테고리의 LLM 세부 CWE가 검증 후 보존됨.
- `exists`, `arg_literal`, `arg_count` 전체가 프롬프트→검증→캐시→TSV로 전달됨.
- critic 기본값은 off. 연구 비교에서만 on.

### G1 — 골든 룰

- 41개 전수 실행, 누락 없이 raw 응답 보존.
- role macro-F1 ≥ 0.85, sink recall ≥ 0.90.
- 고신뢰 항목 중 치명적인 source/sink 역전 0건.
- 미달 시 오류 버킷을 고치고 새 버전의 프롬프트로 전체 재실행한다.

### G2 — Juliet 회귀

- 38개 CWE 엔진 실행 성공률 100%.
- 기존 raw recall 0.895보다 2%p 이상 하락하지 않을 것.
- 취약점 인스턴스 지표와 raw line 지표를 모두 보고한다.
- xss/sensitive/path/weakcrypto 다대다 매핑 테스트를 포함한다.

### G3 — 실제 Java 레포 E2E

- 최소 3개 레포에서 후보 추출→Qwen 룰→spec→taint→API 응답 전체 경로 성공.
- 결과 파일, 생성 룰, 경로, 비용/시간을 보존한다.
- 프로젝트별 실패 원인을 source/sink/CPG/build/CWE-label/critic으로 분류한다.

### G4 — 오픈웨이트 모델 블라인드 비교

- 동일 held-out 표본과 동일 CWE 허용 범위를 사용한다.
- ScanOps와 비교 모델 결과를 모두 고정한 다음 한 번에 채점한다.
- 합격: ScanOps F1과 recall이 최고 비교 모델 대비 각각 5%p 이내.
- 불합격 시 원인을 수정하되, 이미 본 held-out 프로젝트는 튜닝셋으로 이동하고 새로운 held-out으로
  최종 평가한다.

## 6. 변경 규율

- 한 라운드에 하나의 원인만 수정한다.
- 벤치 특정 파일명·메서드명·변수명은 룰과 프롬프트에 넣지 않는다.
- 실패 결과와 raw 응답을 삭제하거나 덮어쓰지 않는다.
- 각 게이트 결과를 `rebuild/out/java_qwen38/` 아래에 버전별로 저장한다.
- 원격 push 전 전체 diff, 재현 명령, 모델 ID, 데이터 해시, 테스트 결과를 최종 보고서에 기록한다.
