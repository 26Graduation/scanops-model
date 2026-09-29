# SC-INFO — self-consistency 정보량 사전등록 (2026-08-17)

> **이 문서는 측정 전에 작성됐다.** 결과를 본 뒤 기준을 바꾸지 않는다.
> 바꾸게 되면 "바꿨다"와 이유를 이 문서 하단에 남긴다.
> 커밋 해시로 작성 시점을 증명한다 (이 파일이 결과 파일보다 먼저 커밋된다).

## §1 질문

`V3_RESULTS.md` §3-4는 self-consistency(k=5, t=4)가 PrimeVul report 144쌍에서
`pair_correct` 0.056 → **0.278** (5배)을 냈다고 보고한다.
그런데 **같은 표에서 F1은 0.612 → 0.543으로 동시에 떨어진다.**

이 동반 이동은 두 가지로 설명될 수 있고, 둘의 함의가 정반대다:

| 가설 | 설명 | 자기증류(#2) 함의 |
|---|---|---|
| **H1 정보 가설** | k=5 투표가 단일 forward에 없는 판별 정보를 만든다 | 증류할 것이 있다 → GPU 투자 정당 |
| **H2 운영점 가설** | t를 올린 것은 "VULNERABLE이라 덜 말하기" = 임계값 이동일 뿐 | 증류할 것이 없다 → 임계값 하나로 공짜. GPU 낭비 |

**H1과 H2는 AUROC로 갈린다.** AUC는 임계값과 무관한 지표라
(`sweep_threshold.py:31-32` 주석에 이 프로젝트가 이미 명시), 운영점 이동만으로는 AUC가 움직이지 않는다.

## §2 왜 지금 이걸 먼저 재는가

이 프로젝트는 입력을 먼저 재지 않아 네 번 연속으로 GPU·시간을 잃었다
(CTX-1 → V3 → V4 A/D/E, `FINAL_ARCHITECTURE_REPORT.md` §2 #5·#7·#8·#9).
`CTX_RESULTS.md`가 남긴 교훈은 **"AUC보다 정보 유입을 먼저 재라"** 였다.

SC-INFO는 그 교훈의 적용이다. **비용 $0** — 필요한 산출물이 전부 로컬에 있다.

## §3 데이터 (기존 산출물, 새로 생성하지 않음)

전부 **동일 모델 v3s42**의 산출물이고, 두 채널이 **같은 항목·같은 순서**다.

| split | n | 채널 A (단일 forward) | 채널 B (SC k=5) |
|---|---|---|---|
| **PrimeVul report (주 검정)** | 288 | `out/v3s42_logprob_primevul_report.jsonl` | `out/v3s42_primevul_report_votes_k5.jsonl` |
| CleanVul_v2 tune (확인용) | 676 | `out/v3s42_logprob_cleanvul_v2_tune.jsonl` | `out/v3s42_cleanvul_v2_tune_votes_k5.jsonl` |

- **gold 라벨 = `meta.label`** (`sweep_threshold.py:37`, `sweep_votes.py:31`에서 확인).
  최상위 `label` 필드는 **예측값**이므로 gold로 쓰지 않는다.
- 채널 A 점수 = `score` (logp_vuln − logp_none 유래 연속값)
- 채널 B 점수 = `n_vuln_votes` ∈ {0,1,2,3,4,5}

> CleanVul_v2는 **report가 아니라 tune** split이다. votes_k5가 tune에만 존재한다
> (`V3_RESULTS.md` §3-4도 "CleanVul_v2 tune split 338쌍, report 미검증"이라 적었다).
> 따라서 CleanVul 결과는 **확인용이며 단독으로 판정에 쓰지 않는다.**

## §4 방법

- AUROC는 `sweep_threshold.py:31-45`의 `auc()` **함수를 그대로 재사용**한다.
  동점 처리(0.5 크레딧)까지 동일해야 채널 간 비교가 성립한다. 재구현하지 않는다.
- ΔAUC = AUC(B) − AUC(A).
- **쌍 부트스트랩 2,000회**: `meta.pair_id` 단위로 재표집한다
  (`V3_RESULTS.md` §2-1이 쓴 "케이스 재표집"과 동일 관례. 쌍 내부 항목은 상관돼 있다).
  **같은 재표집 인덱스를 A·B에 동시 적용**한다(paired). 95% 백분위 CI.
- 난수 시드 **42** 고정.

## §5 사전 등록 게이트

### 파이프라인 건전성 검사 (먼저)

채널 A의 PrimeVul report AUC가 `V3_RESULTS.md` §3-2가 보고한 **0.580** 을
**±0.005 안에서 재현**해야 한다.
재현하지 못하면 **결과를 보고하지 않고 원인을 먼저 규명한다.**

### 주 판정 (PrimeVul report 288건)

| 판정 | 조건 | 다음 행동 |
|---|---|---|
| **SC-INFO-REAL** | ΔAUC > 0 **AND** 95% CI 하한 > 0 | H1 지지. **#2 자기증류 진행**, RunPod 상한 $15 승인 |
| **SC-THRESHOLD-ONLY** | 95% CI가 0을 포함 | H2 지지. **#2 중단**, GPU $0 소진. §6 이월 |
| **SC-INFO-WORSE** | ΔAUC < 0 **AND** CI 상한 < 0 | SC가 정보를 잃는다. #2 중단 |

CleanVul_v2 tune 결과는 **같은 방향인지만 병기**하고, 주 판정을 뒤집는 데 쓰지 않는다.

### 무효화 조건 (해석 금지)

두 채널의 항목 수가 다르거나 `meta.pair_id` 정렬이 어긋나면
**정렬 문제를 먼저 해결하고, 그 전 숫자는 폐기**한다.

## §6 결과가 null일 때의 2차 검사 (이것도 미리 등록한다)

채널 B는 **6단계 이산값**이고 채널 A는 연속값이다.
이산화는 AUC 해상도를 떨어뜨리므로 **B에게 불리한 방향으로 편향**돼 있다.
즉 **양성 결과는 보수적이지만, null 결과는 이산화 때문일 가능성이 남는다.**

그래서 null이 나오면 추가로 잰다:

- **A-coarse**: 채널 A의 `score`를 6개 분위 구간으로 이산화한 뒤 AUC를 잰다.
- **판단**: AUC(A-coarse) ≈ AUC(B) 이면 이산화가 설명이 아니다 → **null 유지**.
  AUC(A-coarse) ≪ AUC(B) 이면 이산화가 B를 눌렀다는 뜻 → **null을 확정하지 않고 §7로 이월**.

## §7 이 검사가 답하지 못하는 것 (미리 적는다)

- 이 검사는 **v3s42 한 모델·k=5 한 설정**에서만 잰 것이다. 다른 k나 다른 모델로 일반화하지 않는다.
- `pair_correct`가 실제로 5배 올랐다는 §3-4의 관찰 자체를 부정하지 않는다.
  이 검사는 **그 이득의 출처**만 가린다.
- SC-THRESHOLD-ONLY가 나와도 **SC를 서빙에서 쓰지 말라는 뜻이 아니다** —
  운영점 이동이라도 `pair_correct`가 필요한 용도에서는 여전히 유효하다.
  다만 **증류로 1회 forward에 옮겨 담을 수는 없다**는 뜻이다.

## §8 산출물

- 스크립트: `rebuild/sc_info_preflight.py`
- 결과: `rebuild/out/sc_info_metrics.json`
- 보고: `rebuild/out/SC_INFO_RESULTS.md`

## §9 사후 변경 기록

(측정 후 기준을 바꾸게 되면 여기에 무엇을·왜 바꿨는지 적는다. 비어 있으면 변경 없음.)
