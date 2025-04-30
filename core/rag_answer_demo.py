import faiss
import json
import numpy as np
from sentence_transformers import SentenceTransformer
import requests
import time

# === 路徑與模型設定 ===
index_path = "embeddings/combined_index.faiss"
meta_path = "embeddings/combined_metadata.json"
ollama_api_url = "http://localhost:11434/api/generate"
ollama_model = "llama3"  # 可替換為你有安裝的模型名稱
# token=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
# === 載入 FAISS 與 metadata ===
index = faiss.read_index(index_path)
with open(meta_path, "r") as f:
    metadata = json.load(f)

# === 向量模型 ===
embed_model = SentenceTransformer("all-MiniLM-L6-v2")

# === 查詢與回應 ===
def rag_answer(query, top_k=2, max_tokens=128):
    t0 = time.time()

    # 向量檢索
    vec = embed_model.encode([query])
    D, I = index.search(np.array(vec), k=top_k)

    selected = []
    for idx in I[0]:
        if idx < len(metadata):
            entry = metadata[idx]
            entry_type = entry.get("source_type", "unknown")
            label = entry.get("id") or entry.get("title") or ""
            selected.append(f"[{entry_type.upper()}] {label}\n{entry.get('text', '')}")

    context = "\n---\n".join(selected)

    prompt = f"""
You are a cybersecurity assistant. Answer the user's question based only on the context provided.

[Context]
{context}

[Question]
{query}

[Answer]
"""

    print("Calling Ollama... Generating response\n")
    response = requests.post(ollama_api_url, json={
        "model": ollama_model,
        "prompt": prompt,
        "stream": True,
        "options": {
            "num_predict": max_tokens
        }
    }, stream=True)

    if response.status_code != 200:
        return f"Error {response.status_code}: {response.text}"

    answer = ""
    for line in response.iter_lines():
        if line:
            chunk = json.loads(line).get("response", "")
            print(chunk, end="", flush=True)
            answer += chunk

    print(f"\nDone. Total time: {round(time.time() - t0, 2)}s\n")
    return answer

# === 主程式 ===
if __name__ == "__main__":
    while True:
        q = input("\nEnter your question (or 'exit'): ").strip()
        if q.lower() == 'exit':
            break
        print("\n=== Ollama Answer ===")
        rag_answer(q)
