# ScanOps V13 배포 — 모델 + 코드그래프 (RAG/Qdrant 없음)

V13 = **파인튜닝 7B 모델 + 코드그래프(taint) 결합.** 벤치마크의 "V13 + 그래프" 성능을
그대로 내려면 **두 부분**이 필요합니다. **벡터DB(Qdrant)는 안 씁니다.**

```
[백엔드] → POST /analyze → [V13 API(:8100)] → ① Ollama 모델(v13)  ── LLM 판정
                                             └ ② 코드그래프(taint) ── 놓친 취약 보강
                                             → OR 결합 → 취약/안전 반환
```

> ⚠️ **모델(gguf)만 Ollama에 올리면 그래프가 빠집니다** — 그래프는 Python 코드라 모델 파일에
> 못 들어갑니다. 아래 ②(API)를 반드시 같이 띄워야 벤치마크 성능이 나옵니다.
> **Qdrant/벡터DB는 설치·실행하지 마세요.**

## 이 폴더 내용
| 파일 | 크기 | 설명 |
|---|---|---|
| `v13_7b_lora.gguf` | 39MB | 파인튜닝 LoRA 어댑터 |
| `Modelfile` | — | Ollama 등록 설정 |
| `README_배포.md` | — | 이 문서 |

> API 코드(`scripts/api_v13.py`, `scanops/`)는 git `main`에 있음 → 서버에서 레포 clone/pull.

## 준비물
- **Ollama** 설치. 디스크 ~5GB(베이스 4.7GB + 어댑터 39MB), RAM ~6GB, GPU 불필요(CPU OK).

## ① 모델 등록 (Ollama)
```bash
ollama pull qwen2.5-coder:7b-instruct                       # 베이스(공개), 1회
cd <이 폴더> && ollama create qwen2.5-coder-security-v13-7b -f Modelfile
ollama list | grep security-v13                             # 확인
```

## ② 그래프 API 실행 (레포 루트에서)
```bash
git clone https://github.com/26Graduation/scanops-model.git && cd scanops-model
pip install fastapi "uvicorn[standard]" pydantic requests httpx sentence-transformers qdrant-client
#  ※ qdrant-client는 import용 라이브러리일 뿐 — Qdrant 서버 실행 필요 없음. V13은 벡터DB 미사용.
uvicorn scripts.api_v13:app --host 0.0.0.0 --port 8100
```

## 동작 확인
```bash
curl http://localhost:8100/health
# → {"status":"ok","version":"13.0.0","system":{"rule":"LLM OR graph(taint)","rag":false}}

curl -X POST http://localhost:8100/analyze -H "Content-Type: application/json" -d '{
  "code":"app.get(\"/p\",(req,res)=>res.send(\"<b>\"+req.query.n+\"</b>\"))",
  "language":"Node.js / Express"}'
# → {"vulnerable":true, "graph":{"verdict":"vuln","reason":"...xss sink 도달"},
#     "votes":{"llm":true,"graph":true}, ...}   ← 그래프가 동작 중
```

## 백엔드(AiRouter) 연동
- `CUSTOM` 엔진 → **`POST http://<서버>:8100/analyze`**, body `{code, language}`.
- 응답 `vulnerable` + `vulnerability`/`severity`/`cvss`로 리포트. `graph.reason`은 근거 표시용.

## 요약
1. **Qdrant/벡터DB 안 씀** — 설치/실행 X.
2. **두 부분**: ① Ollama 모델 등록 + ② 그래프 API(`api_v13`, :8100).
3. 모델만 올리면 그래프가 빠져 성능이 낮아짐 → 반드시 ②까지.
4. 백엔드는 `:8100/analyze`로 연결.

## 성능 참고
- 요청당 ~7초(7B 모델 1회 + 그래프는 즉시). CPU 서빙 가능.
- 재배포/롤백: 어댑터 `.gguf`만 교체 후 `ollama create` 재실행.
