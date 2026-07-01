# ScanOps V13 런북 — 데이터 확장 → 재학습 → 배포 → 평가

작성: 2026-06-30 · 베이스 `Qwen/Qwen2.5-Coder-7B-Instruct` · 배포 `qwen2.5-coder-security-v13-7b`

V13 목표: V12(264개) 학습 부족을 CVEfixes **3,483개**로 해소해 자체 판별력을 끌어올리고,
"자체 7B + 그래프가 대표 벤치에서 Grok 능가"를 정직하게 주장 가능하게 한다.

---

## ⭐ GPU 선택 (가장 많이 헷갈리는 부분)
이 학습은 **7B 4-bit QLoRA**라 GPU가 필수다. 노트북은 **GPU를 자동감지**해 dtype을 맞춘다(bf16/fp16).

| GPU | VRAM | bf16 | 추천도 | 예상시간 |
|---|---|---|---|---|
| **A100** | 40GB | ✅ | ★★★ **1순위** | ~60~90분 |
| **L4** | 24GB | ✅ | ★★ 가성비 대안(유닛 절약) | ~2~3시간 |
| T4 | 16GB | ❌ | ✕ 비권장(느림·OOM위험) | 3~6시간 |

- **결론: Colab Pro에서 런타임 → 런타임 유형 변경 → 하드웨어 가속기 = A100.** 안 잡히면 **L4**.
- T4는 bf16 미지원이라 자동 fp16으로 돌아가긴 하나(노트북이 처리함) 느리고 OOM 위험 → 마지막 수단.

---

## 0. 이미 완료된 것 (로컬, 자동)
- ✅ **NVD RAG 재임베딩**: Qdrant `cve_vulnerabilities` 792 → **8,883** (무효/반려 26 + 중복 225 제거).
  - `python -m scanops.data.build_rag_index` (재실행 가능). 소스 버그도 영구수정.
- ✅ **V13 학습셋**: `data/lora_train_v13.jsonl` (train **3,119**) + `lora_train_v13_val.jsonl` (val **364**).
  - `python -m ml.build_dataset_v13 --n 4000`. CVE-disjoint, OWASP 누수 0, 자가검증 통과.
- ✅ **V12 7B 베이스라인 벤치**: `reports/V13_BASELINE.md` (V13가 넘어야 할 기준선).

## 1. 재학습 (Colab — 유일한 수동 단계)
> 로컬(M3 16GB)은 4-bit QLoRA 불가(bitsandbytes=CUDA 전용). 위 GPU표 참고.

1. Colab에서 **`ml/notebooks/colab_v13_7b.ipynb`** 열기 → 런타임을 **A100**(또는 L4)로 설정.
2. **셀 ①** 실행 → `GPU: A100 ... | bf16지원: True` 확인. (T4면 경고가 뜨지만 진행은 됨)
3. **셀 ②** 실행 → 파일 업로드 창에서 `lora_train_v13.jsonl` + `lora_train_v13_val.jsonl` **둘 다** 선택.
4. **셀 ③** 실행 → 학습 시작. 하이퍼파라미터: r=32 / alpha=64 / dropout=0.05 / MAXLEN=768 / 3 epoch.
   - dtype은 자동(A100/L4=bf16, T4=fp16). OOM 뜨면 셀 안 `MAXLEN=768`을 `640`으로 낮추고 재실행.
5. **셀 ④** 학습곡선 확인 → **val loss가 도중 상승(발산)하면 EPOCHS를 2로 낮춰** 셀 ③ 재실행.
6. **셀 ⑤** 실행 → **`adapter_v13_7b.zip`** 다운로드 (어댑터만, 병합 X).

## 2. 어댑터 → GGUF (Colab, 병합 없음 — 메모리 '병합 금지' 준수)
> 이 단계는 GPU 불필요(작은 어댑터 변환). T4/CPU 런타임이어도 됨.

1. **`ml/notebooks/colab_v13_7b_to_gguf.ipynb`** 열기.
2. 셀 실행 → `adapter_v13_7b.zip` 업로드 → **`v13_7b_lora.gguf`**(~40MB) 다운로드.
   - `convert_lora_to_gguf.py` 사용(어댑터만 GGUF화). 풀모델 병합/양자화 안 함.

## 3. 로컬 배포 (Ollama ADAPTER 방식 — 검증된 방식)
```bash
mv ~/Downloads/v13_7b_lora.gguf models/v13_7b_lora.gguf
cd models && ollama create qwen2.5-coder-security-v13-7b -f Modelfile_v13_7b_DEPLOY
ollama run qwen2.5-coder-security-v13-7b   # 스모크 테스트
```
`Modelfile_v13_7b_DEPLOY` = `FROM qwen2.5-coder:7b-instruct` + `ADAPTER ./v13_7b_lora.gguf` (rp=1.3 고정).

## 4. 평가 (재학습 후 — Grok 비교, 베이스라인 대비)
> ⚡추론 단축: 벤치 스크립트는 num_predict=200으로 설정됨(3줄 출력엔 충분, 추론 9배 빠름).

```bash
# ① OWASP 110 zero-shot — method 추출(프로덕션 경로, 그래프 strong-safe veto가 켜지는 입력)
python scripts/benchmark_v12.py --bench data/owasp_method_bench.jsonl \
    --model qwen2.5-coder-security-v13-7b:latest --grok
# ② CVEfixes held-out 141 — V13 학습서 제외했으므로 valid(실제 CVE 판별력 측정)
python scripts/benchmark_v12.py --bench data/cvefixes_benchmark.jsonl \
    --model qwen2.5-coder-security-v13-7b:latest --grok
# ③ (선택) RAG(8,883) 효과 — 신규 CVE 재현율 별도 검증
python scripts/benchmark_v12.py --bench data/cvefixes_benchmark.jsonl \
    --model qwen2.5-coder-security-v13-7b:latest --rag --limit 60
```
- **베이스라인(`reports/V13_BASELINE.md`)과 비교**: CVEfixes 재현율 1.2%(v12)에서 얼마나 오르는지가 V13 성패.
- 비교축: V13 LLM 단독 / +그래프 하이브리드 / Grok.

## 산출물 목록
| 파일 | 내용 |
|---|---|
| `ml/build_dataset_v13.py` | CVEfixes 학습셋 빌더(누수차단) |
| `scanops/data/build_rag_index.py` | NVD RAG 재임베딩(무효/반려 제거) |
| `ml/notebooks/colab_v13_7b.ipynb` | 7B QLoRA 학습 (**GPU 자동감지** bf16/fp16) |
| `ml/notebooks/colab_v13_7b_to_gguf.ipynb` | 어댑터→GGUF(병합 없음) |
| `models/Modelfile_v13_7b_DEPLOY` | Ollama ADAPTER 배포 |
| `reports/V13_BASELINE.md` | v12 7B vs Grok 사전 베이스라인 |
| `reports/V13_RUNBOOK.md` | 이 문서 |
