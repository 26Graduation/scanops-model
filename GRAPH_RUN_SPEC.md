# GRAPH-SPEC — LLM 생성 taint 스펙 라운드 사전등록 (2026-08-18)

> **이 문서는 측정 시작 전에 확정됐다.** 결과를 본 뒤 기준을 바꾸지 않는다.
> 바꾸면 §10에 무엇을·왜 바꿨는지 남긴다. 사양서가 결과보다 먼저 커밋된다.
>
> **문서 우선순위: 이 파일 > 노션.** 노션은 연구 근거·배경이고, 구현과 판정은 이 파일을 따른다.
> 노션: https://app.notion.com/p/ScanOps-3bc0070cb76480e9b4f6f26920fc20d1 (§6 그래프 이론 / §6-B 룰 표·최신 연구 / §7 평가 설계)

---

## §1 무엇을 하는가

그래프가 juice-shop에서 **정답 라인 적중 0/36**인 원인은 엔진이 아니라 **룰 21개**다.
`routes/login.ts:34`의 `models.sequelize.query(...)`를 코앞에서 지나쳤다 — `sequelize.query`가 sink 목록에 없어서다.

손으로 룰을 수백 개 쓰는 대신 **LLM이 레포마다 taint 스펙을 생성**하게 한다.

| 출처 | 가져오는 것 | 고치는 문제 |
|---|---|---|
| **IRIS** (ICLR 2025) | 프로젝트 API를 LLM이 source/sink로 라벨링 → 스펙 주입 → 결과를 다시 LLM이 오탐 필터 | 룰 21개로 커버 안 되는 문제 (논문: 탐지 27→55) |
| **CPGHunter** (EMSE 2026) | 외부 라이브러리 API의 인자→반환값 **오염 전파 규칙**까지 LLM 생성 | `sequelize.query` 미탐 — Joern이 ORM 내부를 모르는 문제 (논문: precision 0.131→0.287) |

둘은 선택지가 아니라 한 파이프라인의 2단계다.

---

## §2 기준선 (측정 전 확인된 실측값)

`rebuild/out/repo_bench_juice-shop_joern.json` 에서 읽은 값이다. 이 숫자를 임의로 바꾸지 않는다.

| 항목 | 값 |
|---|---|
| 분석 파일 수 | 257 |
| Joern 실행 시간 | 149.0초 (**CPG 빌드만.** LLM 호출 시간 미포함) |
| 총 finding | 3,660 |
| sanitizer 통과 후 finding | **1,337** |
| **파일당 경보 수 (S2-A 기준선)** | **1,337 / 257 = 5.202** |
| 경보가 뜬 파일 | 73 / 257 |
| sanitizer 패턴 수 | 42 |
| **정답 라인 적중** | **0 / 36** |

정답표 `rebuild/data/repo_bench/juice-shop_truth.jsonl`:

| 항목 | 값 |
|---|---|
| 전체 항목 | 44 |
| **코드파일 항목 (`is_code_file=true`)** | **36** ← 라인 채점 대상 |
| 비코드 항목 | 8 ← 별도 집계, 분모 제외 |
| 코드 항목이 걸쳐 있는 **파일 수** | 12 |
| cross_file 표시 | 16 |

> **주의**: 36은 파일 개수가 아니라 **정답 라인 항목 수**다. 한 파일에 정답 라인이 여러 개 있다.
> 분자도 반드시 항목 단위로 센다. "적중한 파일 수 / 36"은 틀린 계산이다.

---

## §3 사전등록 상수 (결과와 무관하게 고정)

| 상수 | 값 | 비고 |
|---|---|---|
| **라인 적중 분모** | **36** (코드파일 정답 항목 수) | 44 아님. 비코드 8건은 별도 집계 |
| **라인 허용 오차** | **±10줄** | |
| **경보 허용 상한** | **S2-A 파일당 경보 × 1.20 = 5.202 × 1.20 = 6.242** | 소수점 3자리까지 원시값 보존, 비교는 3자리에서 |
| **wall-clock 마감** | **2026-08-18 23:00:00 KST** | 이후 새 LLM 호출 시작 금지 |
| **LLM 호출 상한** | 스펙 생성 **300회**, critic **200회** (합 500회) | 배치 처리 필수 (§5) |
| **판정 용어** | `GOAL-MET` / `PARTIAL` / `NOT-MET` 세 개만 | `GO` 표현 사용 금지 |

---

## §4 비교할 arm

| arm | 그래프에 주입하는 것 | 작업량 |
|---|---|---|
| **S1** | 없음 (LLM 단독) | 0 — 기존 측정 재사용 |
| **S2-A** | 손 룰 `taint_v4.sc` 21개 그대로 | **0** — 대조군. IRIS 논문의 "CodeQL 단독 27건" 자리 |
| **S2-B** | **LLM 생성 스펙만** | 이번 라운드 작업 전부 |
| **S2-C** | 손 룰 + LLM 스펙 **합집합** | §4-1 병합 규칙 적용 |

```
주지표 = S2-B − S1      그래프가 무엇을 더했는가
보조   = S2-B − S2-A    LLM 스펙이 손 룰보다 나은가
```

**S1은 v1 모델로 고정한다.** 이 라운드 중 모델을 바꾸면 그래프 덕인지 모델 덕인지 못 가린다.
LLM 재학습(v2)은 이 라운드가 끝난 뒤 별도 라운드.

### §4-1 S2-C 병합 규칙 (사전 확정)

1. 손 룰과 LLM 스펙을 **합집합**으로 주입한다.
2. `(cat, sink 패턴 문자열, field)` 세 값이 모두 같으면 **하나로 병합**한다.
3. 같은 카테고리라도 패턴이 다르면 **둘 다 유지**한다. 어느 쪽도 버리지 않는다.
4. 같은 API를 손 룰은 sink로, LLM은 sanitizer로 본 경우처럼 **역할이 충돌하면 둘 다 유지하고
   충돌 목록을 결과에 기록한다.** 결과를 보고 유리한 쪽을 고르지 않는다.
5. 병합 후 최종 스펙 파일을 저장한다.

---

## §5 파이프라인 (S2-B / S2-C)

```
1. 후보 API 추출        레포에서 외부 호출 API + 내부 함수 파라미터 전부
        ↓
2. LLM 스펙 생성        각 API가 source / sink / sanitizer / 무관 중 무엇인가
                        외부 라이브러리면: 인자 → 반환값 오염 전파 규칙까지
                        ※ 후보를 1건씩 호출하지 말 것. 배치로 묶어 호출한다
        ↓
3. Joern 스펙 변환      taint_v4.sc 의 Rule 형식으로 (ORM/체인 호출은 field="full")
        ↓
4. CPG taint 분석       레포 전체 → source→sink 경로
        ↓
5. 문맥 수집            각 finding의 source 위치 / sink 위치 / 경로 / 주변 코드 / CWE / sanitizer 정보
        ↓
6. LLM critic           이 경로가 실제 취약점인가 → 오탐 제거 (IRIS 5단계)
        ↓
7. 최종 finding
        ↓
8. 라인 단위 채점       critic 전/후 결과를 **둘 다** 기록
```

**그래프 입력은 레포 전체다.** 함수 조각을 먹이면 조각에 source가 없어 unknown 91.6%가 나온다.
이게 지난 실패 원인 1번이다.

**critic 모델은 스펙 생성 모델과 별도로 기록한다.**

---

## §6 채점

```
라인 적중 = 같은 파일 AND |예측라인 − 정답라인| ≤ 10 AND CWE 일치

라인 적중률 = (적중한 정답 항목 수) / 36        ← 항목 단위. 파일 단위 아님

3분류:
  ① 라인 적중
  ② 파일은 적중, 라인 벗어남
  ③ 파일 미도달

함께 기록: 총 finding 수, 파일당 경보 수, unknown 비율,
          critic 전 / critic 후 각각, 비코드 8건 별도
```

기존 채점기는 파일 단위여서 세 arm 모두 recall 1.0으로 포화됐다. 정답표에 라인 번호가 이미 있는데
스코어러가 버리고 있었다.

---

## §7 판정 (결과 확인 전 고정)

```
GOAL-MET : ① S2-B 라인 적중 > S1 라인 적중
       AND ② S2-B 라인 적중 > S2-A 라인 적중
       AND ③ S2-B 파일당 경보 ≤ 6.242        (= S2-A 5.202 × 1.20)

PARTIAL  : 개선은 있으나 ①②③ 전부를 만족하지 못함

NOT-MET  : S2-B 라인 적중 ≤ max(S1, S2-A)
```

- 라인 적중 분모는 **항상 36**이다.
- 파일당 경보 비교는 **critic 적용 후** 값으로 한다. critic 전 값도 함께 기록한다.
- S2-C는 참고 지표다. 판정은 S2-B로 한다.

### 중간 게이트와 최종 판정은 다르다

`0/36 → 1건 이상`은 **개발을 계속할지 판단하는 중간 게이트**일 뿐이다.
이것을 GOAL-MET으로 쓰지 않는다. 최종 판정은 위 ①②③를 쓴다.

### 미달 시

결과를 그대로 기재하고 원인을 분류한다:
**sink 미인식 / source 미인식 / sanitizer 오판 / 파일 간 연결 실패 / 언어 미지원 /
외부 라이브러리 오염 전파 규칙 실패 / critic 오탐 필터 실패 / 기타**

"그래프 성능 부족" 같은 뭉뚱그린 표현은 쓰지 않는다. 실제 finding을 열어보고 분류한다.

NOT-MET이면 폴백: `taint_v4.sc` → `taint_v5.sc` 로 손 룰 추가(노션 §6-B 절차).
채택 조건은 **새로 맞춘 진탐 수 > 새로 생긴 과탐 수**.

---

## §8 데이터

| 데이터 | 역할 | 상태 |
|---|---|---|
| `rebuild/data/repo_bench/juice-shop_truth.jsonl` | 룰 조정 작업대. 44건(코드 36) | 보유 |
| CVEfixes 원본 → 레포 clone 10~15개 | 본 평가. **CVSS 있음** → 과제 목표 충족 | 신규 구축 |

레포 선정 시 **학습에 이미 쓴 CVE는 제외**한다.
① 후보 레포의 CVE-id가 학습셋에 있으면 제외 ② 파일 유사도 95% 이상이면 제외.
**선정 기준과 실제로 고른 레포 목록을 결과에 기록한다.**

juice-shop만으로 부족한 이유: CVSS가 없고(교육용 챌린지) 레포가 하나뿐이라
"대상 시스템 확장"을 보일 수 없다.

외부 레포 측정은 **juice-shop에서 S2-B가 기준선을 넘은 것을 확인한 뒤** 시작한다.
시간이 부족하면 가능한 개수까지만 하고, **수행한 레포 수와 중단 이유를 기록한다.**

---

## §9 하지 말 것

- 벤치의 특정 파일명·함수명·변수명·라인번호를 룰이나 LLM 프롬프트에 넣기 (= 시험지 외우기).
  `routes/login.ts:34` / `routes/search.ts:23`은 **검증용 확인 지점**일 뿐 하드코딩 대상이 아니다.
  일반적인 프레임워크·라이브러리 API 패턴만 쓴다
- 프롬프트 템플릿 변경 (학습 `rebuild/build_dataset.py` / 평가 `rebuild/bench_common.py` /
  서빙 `scripts/api_rebuild.py` 세 곳 바이트 동일 불변식이 깨진다)
- 모델 재학습, LoRA·학습 데이터·학습 설정 변경 (이번 라운드는 v1 고정)
- 그래프의 "안전" 판정으로 LLM 판정 덮기
  — graph=safe 113건 중 48건(42.5%)이 실제 취약이었다
- sanitizer를 sink 카테고리 무시하고 전역 적용 — `applies_to`를 지켜라
- 기존 결과 파일 덮어쓰기. 이번 실행 결과는 별도 파일로 보존한다
- 파일 삭제. 지울 것은 `_to_delete/` 로 옮기고 보고한다
- §3 사전등록 상수를 결과에 맞춰 바꾸기
- 마감(23:00 KST)을 넘겨 숫자를 맞추려고 추가 호출하기.
  상한에 걸리면 checkpoint 저장 → 처리/미처리 후보 수와 목록 기록 → 그 상태로 판정

---

## §10 변경 이력

| 날짜 | 무엇을 | 왜 |
|---|---|---|
| 2026-08-18 | 초판 확정. §2 기준선 실측 반영, §3 사전등록 상수 6개 고정(분모 36 / ±10 / ×1.20 / 23:00 KST / 호출 500 / 판정 용어), §4-1 S2-C 병합 규칙 추가, §5에 critic 단계 추가 | 결과 확인 후 해석이 갈릴 여지를 제거 |

---

## §11 1라운드 결과 — 박제 (2026-08-18, 수정 금지)

> **이 절은 다시 쓰지 않는다.** 사전등록 §7 기준으로 판정된 그대로다.
> 이후 채점 규칙이 바뀌어도 이 표와 판정은 손대지 않는다.

| arm | 경보 | 경보/파일 | 라인 적중 /36 |
|---|---:|---:|---:|
| S1 (v1 단독) | 115 | 0.447 | 0 * |
| S2-A (손 룰) | 1,335 | 5.195 | 0 |
| S2-B (LLM 스펙) | 2,481 | 9.654 | **5** |
| S2-C (합집합) | 3,454 | 13.440 | 5 |
| S2-A + critic | 0 | 0.000 | 0 |
| S2-B + critic | 9 | 0.035 | **3** |
| S2-C + critic | 6 | 0.023 | 3 |

\* S1은 v1 4줄 프롬프트라 출력에 라인 번호가 없다. 라인 적중 0은 구조적이며 성능 지표가 아니다.

**판정: PARTIAL**

```
① S2-B 라인 적중 3 > S1 0                          ✓
② S2-B 라인 적중 3 > S2-A 0                        ✓
③ S2-B 경보/파일 0.035 ≤ S2-A 0.000 × 1.20 = 0.000  ✗
```

### 알려진 사양 결함 (기록만 하고 이번 판정은 유지)

1. **③이 수학적으로 퇴화했다.** 기준선이 0이면 ×1.20도 0이라 어떤 양수도 통과 못 한다.
   그리고 `S2-A_critic = 0`은 "손 룰이 진탐을 하나도 못 냈다"는 뜻이지 "S2-B가 시끄럽다"는 뜻이 아니다.
2. **§6의 "CWE 일치" 조건이 성립 불가였다.** 정답표에 `cwe` 필드가 없다(44/44 None).
   실제로 있는 건 `category`다. 채점기가 임의 매핑으로 우회했고 그 결과 10건이 걸러졌다.

두 결함 모두 §12에서 사전등록으로 고친다. **1라운드 숫자는 재계산하지 않는다.**

### 실패 분포 (S2-B 기준)

| 카테고리 | 건수 | hit | sink 미인식 | CWE 불일치 | critic이 지움 | 언어 밖 |
|---|---:|---:|---:|---:|---:|---:|
| Injection | 10 | 0 | 3 | 5 | 2 | 0 |
| XSS | 3 | **3** | 0 | 0 | 0 | 0 |
| Unvalidated Redirects | 4 | 0 | 4 | 0 | 0 | 0 |
| Broken Access Control | 5 | 0 | 3 | 2 | 0 | 0 |
| Sensitive Data Exposure | 3 | 0 | 0 | 2 | 0 | 1 |
| Observability Failures | 3 | 0 | 2 | 1 | 0 | 0 |
| Improper Input Validation | 2 | 0 | 1 | 0 | 0 | 1 |
| Security through Obscurity | 2 | 0 | 2 | 0 | 0 | 0 |
| Miscellaneous | 2 | 0 | 1 | 0 | 0 | 1 |
| Broken Authentication | 1 | 0 | 1 | 0 | 0 | 0 |
| Broken Anti Automation | 1 | 0 | 1 | 0 | 0 | 0 |
| **합계** | **36** | **3** | **18** | **10** | **2** | **3** |

### 확인된 원인 3개

1. **분모 36에는 taint 그래프가 원리적으로 못 잡는 유형이 섞여 있다.** §12-1에서 분리한다.
2. **critic이 엉뚱한 근거 라인을 받았다.** `routes/search.ts:23`(정답은 `sequelize.query`)에
   28행 `findAll`이 근거로 전달되어 "findAll with no user input"으로 진탐 2건이 제거됐다.
   또 S2-A는 critic이 1,335건을 100% 제거했다. 지금 critic은 과공격적이다.
3. **JS 템플릿 리터럴 보간에서 오염 전파가 끊긴다.**
   진단(`graph_spec_diag_sequelize_juice-shop.json`): `sequelize.query` sink는 3곳 모두 매칭됐고,
   `login.ts:34` / `search.ts:23`은 감싸는 람다 파라미터에 `req`가 있는데도 `flows = 0`이다.
   **sink 미인식이 아니라 데이터플로우 문제다.**

---

## §12 2라운드 사전등록 (측정 전 확정, 2026-08-18)

### §12-1 분모를 두 층으로 분리

`category` 별로 taint 그래프가 원리적으로 도달 가능한지 사전에 고정한다.

| 층 | category | 건수 |
|---|---|---:|
| **T — taint 대상** | Injection, XSS, Unvalidated Redirects | **17** |
| **B — 경계** | Improper Input Validation | 2 |
| **N — taint 비대상** | Broken Access Control, Sensitive Data Exposure, Observability Failures, Security through Obscurity, Broken Authentication, Broken Anti Automation, Miscellaneous | 17 |

- **그래프 단독 성능의 분모는 T = 17**이다. 36이 아니다.
- **하이브리드(v1+그래프) 성능의 분모는 36**이다.
- B(2건)는 어느 분모에도 넣지 않고 별도 집계한다.
- Unvalidated Redirects를 T에 넣는 근거: CWE-601은 `사용자 입력 → redirect sink` 흐름이다.
  우리 11종 카테고리에 601이 없어서 빠져 있었을 뿐이다(노션 §6-B 정정 참조).
- **이 분류는 결과를 보기 전에 고정됐다. 측정 후 항목을 옮기지 않는다.**

### §12-2 category → CWE 매핑표 (사전등록)

정답표에 CWE가 없으므로 category로 매칭한다. 아래가 유일한 허용 집합이다.

| category | 허용 CWE |
|---|---|
| Injection | CWE-89, CWE-78, CWE-94, CWE-943, CWE-77 |
| XSS | CWE-79 |
| Unvalidated Redirects | CWE-601 |
| Improper Input Validation | CWE-20 |
| Broken Access Control | CWE-284, CWE-639, CWE-862, CWE-863 |
| Sensitive Data Exposure | CWE-200, CWE-538 |
| Observability Failures | CWE-778 |
| Security through Obscurity | CWE-656 |
| Broken Authentication | CWE-287, CWE-307 |
| Broken Anti Automation | CWE-799 |
| Miscellaneous | **매핑 불가 — CWE 조건 면제** |

`Miscellaneous`는 CWE 일치를 요구하지 않고 파일+라인만으로 판정한다.

### §12-3 채점 지표를 둘로 분리

```
line_hit_loose  = 같은 파일 AND |예측라인 − 정답라인| ≤ 10          (CWE 무관)
line_hit_strict = line_hit_loose AND 예측 CWE ∈ §12-2 허용 집합
```

- **판정 주지표는 `line_hit_strict`**, `loose`도 반드시 병기한다.
- 두 값의 차이가 곧 "CWE 라벨링 문제로 잃은 건수"다. 이걸 숨기지 않는다.

### §12-4 critic 규칙

1. critic에 넘기는 evidence의 라인은 **그 finding의 sink 라인과 같아야 한다.**
   candidate line과 evidence line이 다르면 버그다. 넘기기 전에 검증하고, 불일치 건수를 기록한다.
2. critic 출력은 **TRUE / FALSE / UNCERTAIN** 3분류다.
3. 최종 채점에는 TRUE만 쓴다. **UNCERTAIN은 삭제하지 않고 보존**하고,
   `TRUE만` / `TRUE+UNCERTAIN` 두 시나리오를 모두 기록한다.
4. FALSE 판정에는 근거로 삼은 라인과 이유를 반드시 남긴다.
5. critic이 한 arm의 finding을 90% 이상 제거하면 **경고로 기록한다.** 정상이 아니다.

### §12-5 경보 게이트 (③ 조건 수정)

```
허용 상한 = max( S2-A 경보/파일 × 1.20 , 1.0 )
```

하한 1.0의 근거: 기준선이 0일 때 비율 게이트가 퇴화하는 것을 막고,
juice-shop 257파일 기준 총 257건 — 사람이 하루에 훑을 수 있는 상한이다.
통계적 기준이 아니라 사용성 기준임을 명시한다.

### §12-6 실험군

| arm | 구성 |
|---|---|
| **R1** | v1 단독 |
| **R2** | 그래프 단독 (LLM 스펙 + 수정된 전파) |
| **R3** | v1 ∪ 그래프 (provenance 유지) |
| **R4** | R3 → LLM verifier → TRUE만 |

provenance를 finding마다 유지한다: `v1-only` / `graph-only` / `overlap`.

**이번 라운드의 핵심 질문은 하나다 — `graph-only` finding 중 실제 TP가 몇 건인가.**
경보 수가 늘어난 것은 성공이 아니다.

### §12-7 2라운드 판정

```
GOAL-MET : ① R2 line_hit_strict(/17) > 1라운드 S2-B critic후 3
       AND ② R3 line_hit_strict(/36) > R1 line_hit_strict(/36)
       AND ③ R4 경보/파일 ≤ max(R2 경보/파일 × 1.20, 1.0)
       AND ④ graph-only TP ≥ 1

PARTIAL  : 개선은 있으나 ①~④ 전부를 만족하지 못함
NOT-MET  : R2 ≤ 3 AND graph-only TP = 0
```

④를 넣은 이유: 그래프가 v1이 이미 찾은 것만 다시 찾으면 그래프를 붙일 이유가 없다.

### §12-8 범위 밖 (이번 라운드에서 하지 않음)

- CVEfixes 외부 레포 평가 — 별도 트랙. 단 **line-level 정답을 만들 수 있는지 조사만 하고 TODO로 남긴다.**
  노션 §1에 원본 DB에 `변경 라인`이 있다고 기록돼 있다. "없다"고 단정하지 말고 확인한다.
- v2 모델 학습
- 프롬프트 템플릿 변경

---

## §13 변경 이력 (§10에서 이어짐)

| 날짜 | 무엇을 | 왜 |
|---|---|---|
| 2026-08-18 | §11 1라운드 결과 박제(PARTIAL). §12 2라운드 사전등록 추가 — 분모 T=17/전체 36 분리, category→CWE 매핑표 고정, loose/strict 지표 분리, critic 3분류 + evidence 라인 검증, 경보 게이트 하한 1.0, R1~R4 실험군, graph-only TP 조건 ④ | 1라운드에서 드러난 사양 결함 2개(경보 게이트 퇴화, CWE 필드 부재)를 결과 확인 **후**가 아니라 다음 라운드 **전에** 고정하기 위해 |

---

## §14 2라운드 결과 — 박제 (2026-08-18, 수정 금지)

| 지표 | 값 |
|---|---|
| Graph strict (T층) | **8 / 17** (1라운드 3 → 8) |
| Graph hit 고유 코드 위치 | **3곳** (`search-result.component.ts`, `routes/login.ts:34`, `routes/search.ts:23`) |
| **cross-file TP** | **8 / 8** |
| **same-file TP** | **0 / 8** |
| Hybrid strict (전체 36) | 8 / 36 |
| critic TRUE 경보 | 15건 / 고유 위치 15 / 고유 파일 11 |
| critic 판정 | TRUE 15 · FALSE 354 · UNCERTAIN 17 · 미판정 6 |
| FALSE 제거율 | 90.31% → **경고 발생** |
| evidence 라인 불일치 | **0** (1라운드 버그 해소 확인) |
| 경보/파일 (R4) | 0.058 |
| **§12-7 판정** | **PARTIAL** |

**개선 원인**: 템플릿 리터럴 전파가 아니라 **source modeling**이었다.
Joern JSSRC가 `METHOD_PARAMETER_IN req` 와 `req.query.q` 사이에 데이터 의존을 만들지 않았고,
parameter-rooted fieldAccess를 source로 추가하자 합성 전파 테스트 5종이 전부 통과했다(clean control 0).

**틀린 것으로 확인된 1라운드 가설 2개** — 기록만 하고 되돌리지 않는다.
1. "critic이 진탐 2건을 잘못 지웠다" → **틀렸다.** evidence 불일치는 0이었고, ±10 귀속 때문에 그렇게 보였다.
2. "CWE-601 룰을 추가하면 Redirects 4건이 회수된다" → **틀렸다.** 정답 위치가 일반 redirect sink가 아니라
   allowlist 문자열·검증 로직이었다. 현재 taint sink 모델로 직접 회수할 대상이 아니다.

### T층 17건 잔여 상태

| 상태 | 건수 |
|---|---|
| strict hit | 8 |
| loose 적중 · strict 실패 (CWE 불일치, Injection) | 3 |
| sink 미인식 (Injection) | 2 |
| Unvalidated Redirects — taint sink 아님 | 4 |

---

## §15 3라운드 사전등록 (측정 전 확정, 2026-08-18)

### §15-1 단위 규약 — 숫자를 섞지 않는다

세 가지는 서로 다른 단위다. 모든 보고에 **단위를 명시**한다.

| 단위 | 뜻 | R2 실측 |
|---|---|---|
| **정답 항목** | 정답표 행 수 | T층 17, hit 8 |
| **고유 코드 위치** | (파일, 라인) 중복 제거 | hit 3곳 |
| **경보 건수** | 도구가 낸 alert 수 | critic TRUE 15 |

"8/17"과 "3곳"을 같은 단위처럼 쓰지 않는다. 배너·보고서도 동일하다.

### §15-2 precision은 하한으로만 보고한다

juice-shop 정답표는 **표시된 44건뿐**이고 레포에는 표시 안 된 실제 취약점이 더 있다.
따라서 정답에 안 맞은 경보를 FP로 단정할 수 없다.

```
precision_lower_bound = (정답 ±10 안에 든 경보 위치 수) / (전체 경보 위치 수)
```

R2 실측: **3 / 15 = 0.20 (하한)**. 파일 단위로는 정답 파일 3 / 경보 파일 11 = 0.27 (하한).
v1은 파일 단위로 정답 파일 10 / 경보 파일 115 = 0.087 (하한).
**단위가 다르므로 "몇 배"로 환산하지 않는다.** 파일 단위끼리만 비교하고 그 사실을 함께 적는다.

### §15-3 보완성 지표 — 우선순위 재정의

| 순위 | 지표 | 정의 | 왜 |
|---|---|---|---|
| **주** | **cross-file TP** | 적중한 정답 중 `cross_file` 또는 `cross_file_candidate`인 건수 | v1은 파일 단위로 읽으므로 **원리적으로** 못 하는 유형. v1 품질과 무관 |
| 보조 | graph-added | 그래프가 낸 finding 중 v1 경보 파일 밖에 있는 것 | 파일 단위 한계를 함께 명시 |
| 참고 | graph-only TP | v1 localization과 라인 비교했을 때 그래프만 잡은 TP | **v1 localization 품질에 반비례한다.** v1이 좋아지면 이 값은 내려간다. **목표로 삼지 않는다** |

`graph-only TP = 0`을 그래프의 보완성 부재 근거로 쓰지 않는다.

### §15-4 실험군

**Graph ablation** — G0 = R1 그래프 / G1 = R2 그래프 / G2 = R2 + 이번 개선
각각 기록: strict /17 · loose /17 · **cross-file TP** · same-file TP · 경보 수 · 경보/파일 · precision 하한

**Fusion arm** — R1 = v1 / R2 = 그래프 / R3 = v1 ∪ 그래프 / R4 = R3 + verifier
finding마다 provenance: `graph-added` / `overlap` / `v1-only`

**v1 localization (L1)** — 선택. 하면 **별도 ablation**으로만 다루고 **R1 arm 자체는 변경하지 않는다.**
기존 학습·평가·서빙 4줄 템플릿을 건드리지 않는 별도 2차 호출로 구현한다(노션 §5⑥과 같은 구조).
L1을 하면 localization 정확도를 먼저 따로 평가한다: 파일 적중 / 라인 strict / 라인 loose / CWE 일치,
그리고 실패 유형(localization 실패 · 잘못된 라인 · 라인 맞고 CWE 틀림 · CWE 맞고 라인 틀림)을 분리한다.

### §15-5 3라운드 판정

**§12-7 기준을 그대로 적용한다. 이번 결과를 보고 바꾸지 않는다.**
④ `graph-only TP ≥ 1`이 §15-3에 따라 부적절한 조건임을 알고 있으나, 사전등록이므로 그대로 평가한다.

그와 **별도로** capability 분석을 병기한다.

```
C1  Graph strict(/17)  > R2의 8            인가
C2  cross-file TP      ≥ R2의 8            인가
C3  graph-added TP     ≥ 1                 인가
C4  Hybrid strict(/36) > R2의 8            인가
C5  경보/파일          ≤ max(G1 × 1.20, 1.0) 인가
C6  verifier가 제거한 TP 수 = 0            인가
```

C1~C6는 사양 판정을 대체하지 않는다. `§12-7 판정`과 `C1~C6 분석`을 **둘 다** 적는다.

### §15-6 범위 밖

- v1 재학습, v2 학습 — 금지
- 학습·평가·서빙 프롬프트 템플릿 변경 — 금지
- CVEfixes 외부 평가 — 조사만 계속, R3 작업을 방해하지 않는 선에서

### §15-7 v2 판단은 R3 이후

| 관측 | 다음 행동 |
|---|---|
| A. recall 증가 + cross-file TP 유지 | 그래프 방향 유지. v2는 line-level + graph-context 학습으로 별도 검토 |
| B. recall 정체이나 source/sink/classification에 명확한 개선점 | 그래프 표현·룰 개선 우선 |
| C. cross-file은 잘 잡고 same-file·타 클래스는 못 잡음 | 그래프 역할을 **cross-file data-flow detector**로 명시하고 계층 분리 설계 |
| D. 그래프 개선 한계 + v1 localization 한계 명확 | 그때 v2 학습 검토 |

---

## §16 L1 (v1 localization) ablation 사전등록 (측정 전 확정, 2026-08-22)

`rebuild/out/GRAPH_SPEC_RESULTS_R4.md` §9 권고를 그대로 실행한다. §15-4 제약(별도 ablation,
R1 arm 불변, 4줄 템플릿 불변, 별도 2차 호출, provenance 반영 전 정확도 선평가)을 구체화한다.

### §16-1 범위

- 입력: **기존** `rebuild/out/repo_bench_juice-shop_s1.jsonl`(R1 raw, 재사용 — 재실행하지 않는다)에서
  `label == "vuln"` 인 파일 전부(257개 중 115개).
- `rebuild/repo_bench_scan.py::cmd_s1` / `PROMPT_TMPL` / `scripts/api_rebuild.py` 는 **읽기만** 한다.
  한 글자도 고치지 않는다.
- v1이 "safe"라고 한 파일에는 L1을 돌리지 않는다 — L1은 v1의 기존 vuln 판정에 라인을 붙이는
  2차 호출이지, 새로운 1차 탐지가 아니다.

### §16-2 모델·백엔드 (사용자 확정, 2026-08-22)

- **베이스 Qwen3.5-9B(`models/Qwen3.5-9B-Q4_K_M.gguf`), LoRA 어댑터 없음**, 로컬 llama-server.
- 기각한 대안과 이유: v1 어댑터(`adapter_v1_fix.gguf`) 재사용은 4줄 포맷 전용으로 좁게
  파인튜닝돼 있어 다른 질문(LINE만 요구)에 대한 응답 품질이 검증되지 않음(거부·붕괴 위험).
  외부 API(claude-opus-5)는 R4가 이미 명시한 "소스코드 외부 전송 0" 제품 요구사항 위반을
  이번에도 반복하게 됨.
- 기동: `llama-server -m models/Qwen3.5-9B-Q4_K_M.gguf -c 16640 --parallel 1 --host 127.0.0.1
  --port 8080 -ngl 99` (어댑터 플래그 없음). `--parallel N`이 컨텍스트를 슬롯당 N등분하는
  함정이 실측돼 있으므로 `--parallel 1` 고정(HANDOFF_V4.md §5).
- temperature 0 (greedy) — v1 측정과 동일한 결정성 관례를 따른다.
- 8080 포트에 있던 `adapter_v3_16k.gguf`(붕괴·배포 금지 모델) 프로세스는 이번 라운드 시작 전
  종료했다.

### §16-3 호출 설계 — 별도 2차 호출

- **입력**: 파일 전체(청크 아님) + 1-based 줄번호. 줄번호 부여 함수는
  `rebuild/prompt_v2.py::format_source_with_line_numbers`를 재사용한다 — 이 함수는 순수 텍스트
  포매터이고 붕괴한 v2/v3 학습·가중치와 무관하므로 재사용해도 "템플릿 불변식"을 어기지 않는다.
  v1이 이미 결론 낸 CWE id/CWE name/REASON(R1 raw의 첫 vuln 청크)을 **사실로 프롬프트에 제공**한다
  — L1은 재탐지가 아니라 국소화(localization)만 한다.
- **새 프롬프트**: `rebuild/l1_localize_run.py`에 한 번만 정의한다. v1 FROZEN
  `PROMPT_TMPL`(4줄)과도, 붕괴한 `PROMPT_TMPL_V2`(재탐지+LINE 5줄)와도 다른 별도 문자열이다.
  요청 출력 형식은 `LINE: <n>` 한 줄만 요구한다.
- **대형 파일**: 관측된 vuln 파일 중 최대 40,368자(`server.ts`, v1 기준 4청크). 컨텍스트
  16,640 토큰에 whole-file로 들어간다(별도 청크 분할 없음). 만에 하나 컨텍스트 초과로 잘리면
  해당 파일을 `truncated` 로 기록하고 `localization_실패`로 분류한다 — 조용히 넘기지 않는다.
- n_predict 예산·재개 가능 여부·raw 보존은 `cmd_s1` 패턴을 그대로 따른다(§CLAUDE.md 결과 보고 규칙).

### §16-4 채점 (측정 전 확정)

기존 §12-2 CWE 매핑표·§12-1 층 분류·`LINE_TOL=10`을 그대로 재사용한다
(`rebuild/graph_spec_score_r2.py::cwe_ok`, 새 규칙 만들지 않음).

```
file_hit        = 정답 항목의 sink_file ∈ v1 vuln 파일 집합(115개)   ← L1을 돌릴 수 있었는가
line_hit_loose  = file_hit AND L1 라인 파싱 성공 AND |L1라인 − 정답라인| ≤ 10
exact_line      = file_hit AND L1 라인 == 정답라인 (오차 0)
line_hit_strict = line_hit_loose AND cwe_ok(category, v1의 CWE)      (§12-2 그대로, CWE는 v1 것)
```

분모는 **36**(코드 항목 전체). 12곳(고유 파일) 기준도 병기한다(§15-1 단위 규약).

**실패 4종 분리** (§15-4 문구 그대로, 상호 배타적 분할 — line_hit_strict 성공 건은 4종에 포함하지 않는다):

| 분류 | 조건 |
|---|---|
| **localization 실패** | `file_hit`가 False (v1이 애초에 그 파일을 vuln으로 못 찍음) **또는** file_hit인데 L1이 라인을 파싱 못함/컨텍스트 초과 |
| **잘못된 라인** | file_hit, L1이 라인을 냈으나 `line_hit_loose` False **그리고** `cwe_ok` False (둘 다 틀림) |
| **라인 맞고 CWE 틀림** | `line_hit_loose` True, `cwe_ok` False |
| **CWE 맞고 라인 틀림** | `line_hit_loose` False, `cwe_ok` True |

### §16-5 하지 않는 것 (이번 라운드 범위 밖)

- provenance(`v1-only`/`graph-only`/`overlap`) 재계산 — §16-4 정확도를 먼저 확정한 **다음** 라운드.
- R1 arm 재실행, R2~R4 결과 파일 수정 — 전부 읽기 전용 참조만.
- CVEfixes 파일럿 확대 재실행 — HANDOFF_V4.md §2-1이 이미 구조적 원인(F_A/F_B/F_C)으로 닫았다.
- 모델 재학습.

### §16-6 판정

R4 §8과 같은 원칙: 이번 라운드는 성능 목표가 아니라 **§16-4 지표 전부를 숫자로 확정**하는 것이
목표다. 사전에 정한 정확도 임계값(GOAL-MET 기준)은 없다 — L1의 실측치 자체가 다음 라운드

---

## §17 L1 top-N 확장 사전등록 (측정 전 확정, 2026-08-22)

### §17-0 배경 — §16 실측 결과와 사용자 결정

`rebuild/out/L1_RESULTS.md`. §16의 파일당 1콜 설계에서 file_hit 9개 파일 중 8개가 정답 라인
2곳 이상(§16-4에 없던 사후 분해, 원 수치는 불변)이었고, 실패 26건 중 13건(server.ts 8 +
app.routing.ts 5)이 "1콜=1라인" 설계 상한이었다. 반대로 정답이 한 곳에 몰린 파일에서는
strict 100%(login.ts 3/3, search.ts 2/2). 사용자가 ROADMAP.md Phase 3에서 **(b) top-N 확장 후
provenance 재계산**을 선택했다(2026-08-22).

### §17-1 범위 — 벤치 과적합 금지 (CLAUDE.md 규칙 4)

**115개 v1-vuln 파일 전부에 균일하게 top-N을 적용한다.** "정답표를 보고 다중-정답 파일에만
top-N을 쓴다"는 금지 — 정답표는 채점에만 쓰고 설계 입력(어느 파일에 몇 개를 물을지)으로
쓰지 않는다. 실전에서는 정답표가 없으므로 이 구분을 지금 어기면 이후 provenance 재계산
결과가 juice-shop에만 맞춘 것이 된다.

### §17-2 N값과 호출 설계

- **N = 3.** 파일당 호출은 여전히 **1회**(§16-3의 "별도 2차 호출" 원칙 유지, 호출 수를 3배로
  늘리지 않는다) — 한 번의 응답에서 순위가 있는 후보 최대 3개를 받는다.
- 프롬프트는 `rebuild/l1_localize_topn_run.py`에 새로 정의한다(§16-3의 top-1 프롬프트도
  그대로 남겨 재현 가능하게 보존 — 덮어쓰지 않는다). 입력은 §16-3과 동일(파일 전체 + 줄번호 +
  v1의 CWE/REASON을 사실로 제공).
- 요청 출력 형식: `LINE_1: <n>` / `LINE_2: <n>` / `LINE_3: <n>` (모델이 확신하는 순서, 자신
  없으면 0). 파싱 실패·중복 라인은 그대로 기록하고 버리지 않는다.
- 모델·백엔드·temperature는 §16-2와 동일(베이스 Qwen3.5-9B, 어댑터 없음, 로컬, greedy).

### §17-3 채점 (top-1과 나란히, 새 규칙 재사용)

`graph_spec_score_r2.py::cwe_ok`, `LINE_TOL=10`, §12-2 매핑 그대로 재사용.

```
line_hit_loose_topN  = file_hit AND (후보 중 하나라도 |후보라인 − 정답라인| ≤ 10)
exact_topN           = file_hit AND (후보 중 하나라도 정답라인과 정확히 일치)
line_hit_strict_topN = line_hit_loose_topN AND cwe_ok(category, v1의 CWE)   (§16과 동일, CWE는 v1 것)
```

§16-4의 실패 4종 분류를 동일 구조로 재사용하되, "잘못된 라인"의 정의만
"N개 후보 **전부**가 loose 실패"로 바뀐다. 나머지 3종 정의는 §16-4와 동일.

**top-1(§16) 대비 비교표를 반드시 병기한다**: 파일별 loose/strict, 특히 §16-4에서 이미
strict 100%였던 `routes/login.ts`(3/3)·`routes/search.ts`(2/2)가 top-N에서도 유지되는지
— 후보가 늘면서 오답이 섞여 strict가 떨어지는 회귀가 없는지 반드시 확인한다.

### §17-4 판정 (결과 확인 전 고정)

```
GOAL-MET : ① line_hit_loose_topN(/36) > line_hit_loose_top1(/36) = 19
       AND ② login.ts(3/3)·search.ts(2/2) 의 strict 가 top-N 에서도 유지(회귀 없음)

PARTIAL  : ①은 만족하나 ②에서 회귀가 있음, 또는 ①은 미달이나 회귀도 없음

NOT-MET  : line_hit_loose_topN ≤ 19 그리고 회귀도 있음
```

GOAL-MET → §17-5(provenance 재계산)로 진행. PARTIAL/NOT-MET → ROADMAP.md Phase 5에서 멈추고
N을 키울지, 다른 방향(R4 우선순위 A, v1 CWE 매핑 조사)으로 갈지 사용자에게 다시 확인한다.
"다음 값으로 재시도"를 사전등록 없이 반복하지 않는다(§CLAUDE.md 규칙 3 — 한 번에 한 변수).

### §17-5 provenance 재계산 설계 (§17-4 GOAL-MET 시에만 실행)

`graph_spec_score_r2.py::merge_provenance`를 라인 단위로 확장한다: v1의 파일별 top-N 라인
후보 vs 그래프 finding의 라인을 `LINE_TOL=10`으로 비교해 `overlap`/`graph-only`/`v1-only`를
정한다(현재는 파일 단위로만 겹침을 봄 — §12-3의 알려진 한계). §12-7④/§15-5 C3(`graph-only
TP ≥ 1`)를 이 라인 단위 provenance로 재평가한다. 이게 L1을 시작한 원래 이유다(R4 §9 근거 1).

### §17-6 하지 않는 것

- 정답표를 보고 파일별로 다른 N을 주는 것 (§17-1).
- 모델 재학습, 4줄 템플릿 변경 — §16-5와 동일하게 범위 밖.
- v1 CWE↔§12-2 매핑 불일치(chat.ts/user.ts) 수정 — 사용자가 (b)만 선택했고 (d)는 별도
  라운드 후보로 남겨둔다(한 번에 한 변수).

### §17-7 결과 — 박제 (2026-08-22, 수정 금지)

`rebuild/out/l1_score_topn_juice-shop.json`, `rebuild/out/l1_provenance_juice-shop.json`.

| 지표 | top-1(§16) | top-N(§17) | Δ |
|---|---:|---:|---:|
| line_hit_loose /36 | 19 | **24** | +5 |
| line_hit_strict /36 | 10 | **14** | +4 |
| exact_line /36 | 14 | **17** | +3 |

**§17-4 판정: GOAL-MET** (① 24>19 ② 회귀 없음 — login.ts/search.ts strict 5/5 유지)

**§17-5 provenance 재계산 (§12-7④/§15-5 C3 재평가)**: R4 최종 arm(그래프+critic TRUE 21건,
재실행 안 함)의 진탐 12건 전부를 라인 단위로 재분류. **graph-only TP 0건** — 파일 단위 원
판정(0건)과 동일, 재분류(overlap↔graph-only 뒤바뀐 건) 0건, ambiguous(L1 후보 없음) 0건.

**결론**: §12-7④/§15-5 C3는 R2·R3·R4에 이어 **라인 단위로 재확인해도 그대로 미달**이다.
R4 §9가 "L1 없이는 이 조건을 영원히 답할 수 없다"고 했던 그 질문에 처음으로 확정된 답이
나왔다 — **이건 v1이 라인을 못 내서 생긴 측정 artifact가 아니라, 그래프의 진탐 12건이
전부 v1의 top-N 라인 후보와 실제로 겹치는 위치라는 사실**이다(진탐 중 v1이 그 파일을
안 찍었거나 후보가 다 빗나간 경우가 0건). juice-shop 표본(n=1, 고유 위치 12곳, R4 STEP1)
한계 안에서는, 그래프가 v1과 "다른 곳"에서 진짜로 새로 찾아낸 것이 없다.

---

## §18 외부 레포 채점 개선 (PLAN.md 3단계, 측정 전 확정, 2026-08-22)

배경: PLAN.md 2단계(`rebuild/out/ext_repo_score.json`)에서 레포별 LLM 스펙으로 외부 3레포
strict 0/13 → 7/13. 그런데 exact(정답 줄 그 자체)는 1/13뿐이라 나머지는 대부분 ±10줄 근접
매치다. PLAN.md 3단계 지시: "탐지 로직은 안 건드림 → 경보 안 늘어남. 채점 기준 변경이므로
먼저 문서에 적고 커밋한 뒤 측정." 사용자가 대화 상대(GPT)의 조언을 받아 이 순서를 확정했다
(경로 기반 채점 추가, jquery-ui 오탐 필터는 3단계와 분리해서 별도로 본다).

### §18-1 채점 재실행 안 함 원칙

`graph_spec_run.py`를 다시 돌리지 않는다. 기존 arm 결과(`graph_spec_arm_S2B/S2C_{repo}.json`,
2단계에서 이미 생성됨)를 그대로 읽는다 — 그 finding들이 이미 `path`(source→sink 경로, 최대
12스텝, 각 노드에 file/line/code/role)를 담고 있다(`joern/queries/taint_spec.sc`가 기록).

### §18-2 4분류 정의 (기존 §12-3/r4_cvefixes_pilot.py::score 정의를 대체하지 않고 병기)

```
exact     = 같은 파일 AND finding.line == 정답라인                         (기존과 동일)
near      = 같은 파일 AND |finding.line − 정답라인| ≤ 10                    (기존 loose와 동일)
strict    = near AND CWE 일치                                              (기존과 동일)
path_hit  = 같은 파일의 어느 finding이든 그 path 배열의 노드 중 하나가
            (file, line) == (정답파일, 정답라인) 과 정확히 일치            (신규 — §18 핵심)
miss      = 위 넷 다 아님
```

- `path_hit`은 그 finding 자체의 sink 줄이 아니어도 된다 — 정답 줄이 **오염 전파 경로 위
  어딘가**(source/intermediate/sink 무관)에 있으면 인정한다. GPT 제안 문구("정답 줄이
  graph data-flow path에 포함되는가") 그대로.
- 허용오차 없이 **정확히 일치**만 본다(Joern이 기록한 줄 번호이므로 반올림·근사 필요 없음).
  0이 나오면 그때 허용오차 도입을 검토하되, 그건 이 실행에서 하지 않는다(§CLAUDE.md 규칙 3).
- 한 정답 항목에 여러 분류가 동시에 참일 수 있다(예: near 이면서 path_hit). **넷을 각각
  독립적으로 집계**하고, 표 요약에서는 exact > path_hit > near > miss 우선순위로 대표 등급 하나만
  추가로 매긴다(GPT 표 형식).

### §18-3 juice-shop 재채점 안 함

PLAN.md 2단계 지시("juice-shop G2 도 재실행하지 말고 기존 결과 그대로 둬라")를 3단계에도
유지한다. §18은 외부 3레포에만 적용한다.

### §18-4 jquery-ui 경보 5,198건은 별도 취급

3단계 결과에 섞지 않는다. 필요하면 §18과 별도로 `graph_spec_critic_r3.py`(살아있는 verifier,
§16-2/HANDOFF_V4.md §3-1)를 jquery-ui에 돌려 경보 축소 여부만 따로 본다 — 사용자 승인 후.

---
(그래프 표현력 A, provenance 재계산)의 입력이 된다.
