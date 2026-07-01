# ScanOps V12 런북 — 과적합 차단 재설계

**핵심:** V11은 OWASP를 학습에 넣고 OWASP로 평가해 데이터 누수가 있었다.
V12는 **OWASP를 학습에서 100% 제외**하고, OWASP·CVEfixes 두 외부 벤치마크를
zero-shot으로 평가한다. 높은 점수 = 외운 게 아니라 일반화의 증거.

---

## 파이프라인 한눈에

```
[1] 데이터셋(OWASP 0%)  →  [2] Colab QLoRA 학습  →  [3] GGUF→Ollama
                                                          ↓
[6] 보고서  ←  [5] 2벤치 4-way 평가(LLM/RAG/그래프/Grok)  ←  [4] 다언어 그래프
```

## 산출물 (이번에 만든 것)

| 단계 | 파일 | 상태 |
|---|---|---|
| 데이터셋 빌더 | `ml/build_dataset_v12.py` | ✅ |
| paired 케이스 뱅크 | `scripts/v12_cases.py` (66쌍, OWASP-free) | ✅ |
| 학습셋 | `data/lora_train_v12_clean.jsonl` (239) + `_val.jsonl` (25) | ✅ |
| Colab 노트북 | `ml/notebooks/colab_v12_3b.ipynb` | ✅ (형이 실행) |
| 다언어 그래프 | `scanops/core/multi_graph.py` (Py/PHP/Go/C#/Ruby/Node/TS) | ✅ |
| 그래프 테스트 | `tests/test_multi_graph.py` (10 pass) | ✅ |
| CVEfixes 벤치 | `data/cvefixes_benchmark.jsonl` (157, 10언어, 2024 CVE) | ✅ |
| 벤치 빌더 | `scripts/build_cvefixes_benchmark.py` | ✅ |
| GGUF 변환 | `scripts/convert_to_gguf_v12.py` | ✅ |
| 4-way 평가 | `scripts/benchmark_v12.py` | ✅ (모델 대기) |

데이터셋 검증: OWASP 흔적 0 · OWASP홀드아웃 누수 0 · train/val 겹침 0 · 16개 언어.

## 과적합 차단 장치 (교수님 설명용)

1. **OWASP 학습 0%** — 서블릿 코드 hash로 원천 배제. OWASP는 zero-shot 평가만.
2. **벤치마크 코드 hash dedup** — OWASP 홀드아웃·CVEfixes 코드를 학습에서 제외.
3. **train/val 분리** — Colab에서 매 epoch val loss로 과적합 감시.
4. **2개 독립 벤치마크** — OWASP(인젝션형) + CVEfixes(실제 2024 CVE, 다언어).
5. **그래프 규칙은 언어 시맨틱 기반** — 평가셋 케이스를 보고 튜닝하지 않음
   (V11 decoy 손튜닝 = 분석기 과적합이었음). strong-safe만 veto해 false-veto 차단.

---

## 형이 Colab에서 할 일 (Task 2)

1. `ml/notebooks/colab_v12_3b.ipynb` 를 Colab에서 열기
2. 런타임 → T4 GPU
3. 셀 ①②③④⑤⑥ 순서 실행 (②에서 `lora_train_v12_clean.jsonl` + `_val.jsonl` 업로드)
4. 셀 ④에서 val loss ✅/⚠️ 확인 (⚠️면 알릴 것)
5. 셀 ⑥에서 `adapter_v12.zip` 다운로드

## 학습 후 로컬 (내가 진행)

```bash
cd scanops-model && source .venv/bin/activate
# 1) 어댑터 풀기
unzip ~/Downloads/adapter_v12.zip -d models/qwen-security-qlora-v12
# 2) GGUF 변환 + Ollama 등록 → qwen2.5-coder-security-v12
python scripts/convert_to_gguf_v12.py
# 3) 벤치마크 ① CVEfixes (다언어 실제 CVE)
python scripts/benchmark_v12.py --bench data/cvefixes_benchmark.jsonl \
    --model qwen2.5-coder-security-v12:latest --grok
# 4) 벤치마크 ② OWASP (zero-shot; 모델명만 v12로)
python scripts/benchmark_hybrid_owasp.py   # MODEL_V11 → v12로 바꿔 실행
# 5) RAG 추가 비교(선택)
python scripts/benchmark_v12.py --bench data/cvefixes_benchmark.jsonl \
    --model qwen2.5-coder-security-v12:latest --rag
```

## 예상되는 결과 해석 (정직한 시각)

- **OWASP**: 그래프(java_graph)가 인젝션 decoy를 가려 하이브리드가 강할 것.
- **CVEfixes**: 실제 CVE는 미묘한 로직 결함 → **정규식 그래프는 거의 unknown**
  (157중 confident 3건). 여기선 **LLM/RAG가 주력**. 점수는 OWASP보다 낮게,
  Grok과 접전이 정상. 이게 오히려 "OWASP에 과적합 안 했다"는 정직한 증거.
- 두 벤치의 성격 차이(인젝션 vs 로직)를 보여주는 것 자체가 강한 메시지.
