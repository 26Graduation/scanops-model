# rebuild/out/ 파일 안내

생성 스크립트별로 묶어서 정리. `*_predictions.jsonl`은 건별 원본 예측(모델의 raw 출력 포함),
`*_report.json`은 집계 숫자(재현율/오탐률/F1, 언어별, 쌍 단위)다.

## 학습 산출물
| 파일 | 내용 |
|---|---|
| `adapter/` | 학습된 LoRA 어댑터 본체 + 토크나이저 세트 (train_qlora.py) |

## 내부 test 채점 (CVEfixes 1,197건)
| 파일 | 내용 | 만든 스크립트 |
|---|---|---|
| `test_predictions.jsonl` | 우리 모델의 건별 예측 | eval_test.py |
| `test_report.json` | 우리 모델 집계 (CWE/SEV 일치율 포함) | eval_test.py |
| `compare_claude_predictions.jsonl` / `compare_claude_report.json` | Claude(sonnet-5) 예측·집계 | compare_apis.py |
| `compare_grok_predictions.jsonl` / `compare_grok_report.json` | Grok-4 예측·집계 | compare_apis.py |
| `compare_claude.log` / `compare_grok.log` | 실행 로그 | 〃 |

## 외부 벤치마크 (PrimeVul 360건 / CleanVul 11,580건 — CWE 채점 없음, 이진+쌍 단위)
| 파일 | 내용 | 만든 스크립트 |
|---|---|---|
| `external_primevul_predictions.jsonl` / `external_primevul_report.json` | 우리 모델 | eval_external.py (pod) |
| `external_cleanvul_predictions.jsonl` / `external_cleanvul_report.json` | 우리 모델 | 〃 |
| `compare_claude_primevul_predictions.jsonl` / `..._report.json` | Claude | compare_claude_external.py |
| `compare_claude_cleanvul_predictions.jsonl` / `..._report.json` | Claude | 〃 |
| `claude_batch_primevul.id` / `claude_batch_cleanvul.id` | Batch API 배치 ID (재실행 시 이중과금 방지용 — 채점 끝났으면 지워도 됨) | 〃 |
| `claude_ext_primevul.log` / `claude_ext_cleanvul.log` | 배치 제출·폴링 로그 | 〃 |

## 오탐(FP) 감사 (심판: claude-opus-4-8)
| 파일 | 내용 |
|---|---|
| `audit_claude_fp.jsonl` | Claude 오탐 100건(층화)의 건별 판정 (VALID/INVALID/UNCERTAIN + 심판 근거) |
| `audit_ours_fp.jsonl` | 우리 모델 오탐 101건(전수)의 건별 판정 |
| `audit_report.json` | 감사 집계 — Claude VALID 13% / 우리 VALID 3% |
| `audit_review_sheet.md` | **★ 사람이 체크할 수동 재확인 시트 (각 10건, 동의/비동의 체크박스)** |
| `audit_run.log` | 실행 로그 |

## 정답 대조표 (엑셀로 열기 — make_comparison.py)
| 파일 | 내용 |
|---|---|
| `comparison_internal.csv` | 내부 test 1,197행: 정답 vs 우리 답 vs Claude 답 (판정/CWE/사유/정오) |
| `comparison_primevul.csv` | PrimeVul 360행 〃 |
| `comparison_cleanvul.csv` | CleanVul 11,580행 〃 |

코드 원문은 CSV에 없음(용량) — `row` 컬럼 번호로 `data/{test,primevul_test,cleanvul_test}.jsonl`의
같은 행을 찾으면 prompt 안에 코드가 있다.
