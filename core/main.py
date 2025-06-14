import faiss
import json
from sentence_transformers import SentenceTransformer
from llama_cpp import Llama
from agents import threathunt_pipeline_full

# Load FAISS index and metadata
index = faiss.read_index("combined_index.faiss")
with open("combined_metadata.json") as f:
    metadata = json.load(f)

# Load embedding model
embed_model = SentenceTransformer("all-MiniLM-L6-v2")

# Load Mistral model (GGUF)
llm = Llama(model_path="mistral-7b-instruct.Q4_K_M.gguf", n_ctx=2048, n_threads=4)

# Interactive QA loop
if __name__ == "__main__":
    while True:
        q = input("\nEnter your question (or 'exit'): ").strip()
        if q.lower() == 'exit':
            break

        print("\n=== Agent Answer ===")
        try:
            result = threathunt_pipeline_full(q, metadata, llm)

            print("\n[CTI Agent]")
            print(result["cti_agent"])
            print("\n[TTP Agent]")
            print(result["ttp_agent"])
            print("\n[Answer Agent]")
            print(result["answer_agent"])

            # response = threathunt_pipeline_full(q, metadata, llm, return_mode="text")
            # print(response)

        except Exception as e:
            print(f"Error: {e}")
