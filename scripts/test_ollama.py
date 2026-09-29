import json
import time
import urllib.request

API_URL = "http://localhost:11434/api/generate"
MODEL   = "gemma:2b"
PROMPT  = "What is CVE? Answer in 2 sentences."


def generate(prompt: str, model: str) -> tuple[str, float]:
    payload = json.dumps({
        "model": model,
        "prompt": prompt,
        "stream": False,
    }).encode()

    req = urllib.request.Request(
        API_URL,
        data=payload,
        headers={"Content-Type": "application/json"},
        method="POST",
    )

    start = time.perf_counter()
    with urllib.request.urlopen(req) as resp:
        body = json.loads(resp.read())
    elapsed = time.perf_counter() - start

    return body["response"], elapsed


def main():
    print(f"Ollama API 연결 테스트")
    print(f"  모델  : {MODEL}")
    print(f"  질문  : {PROMPT}\n")

    try:
        answer, elapsed = generate(PROMPT, MODEL)
        print(f"[응답]\n{answer}\n")
        print(f"응답 시간: {elapsed:.2f}초")
        print("Python API 연결: 성공")
    except Exception as e:
        print(f"Python API 연결: 실패 ({e})")


if __name__ == "__main__":
    main()
