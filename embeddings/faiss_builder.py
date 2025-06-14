import os
import json
import faiss
import numpy as np
from sentence_transformers import SentenceTransformer

entries = []

def load_cti(folder_path):
    for filename in os.listdir(folder_path):
        if filename.endswith(".json"):
            with open(os.path.join(folder_path, filename), 'r') as f:
                cti = json.load(f)

            title = cti.get("title", "").strip()
            summary = cti.get("summary", "").strip()
            techniques = cti.get("techniques", [])

            if summary:
                entries.append({
                    "source_type": "cti_summary",
                    "title": title,
                    "text": summary
                })

            if techniques:
                # 支援格式: list of strings (["T1059.001", ...]) 或 list of dicts ([{"id": "T1059.001"}, ...])
                if isinstance(techniques[0], str):
                    technique_ids = techniques
                elif isinstance(techniques[0], dict):
                    technique_ids = [t.get("id", "") for t in techniques if "id" in t]
                else:
                    technique_ids = []

                if technique_ids:
                    entries.append({
                        "source_type": "cti_techniques",
                        "title": title,
                        "text": " ".join(technique_ids)
                    })

if __name__ == "__main__":
    print("Loading data...")
    load_cti("threat_intel_examples")

    # clean entries with text
    entries = [e for e in entries if e.get("text", "").strip()]
    print(f"Loaded {len(entries)} entries.")

    print("Generating embeddings...")
    model = SentenceTransformer("all-MiniLM-L6-v2")
    texts = [e["text"] for e in entries]
    embeddings = model.encode(texts, show_progress_bar=True)

    print("Building FAISS index...")
    dim = embeddings.shape[1]
    index = faiss.IndexFlatL2(dim)
    index.add(np.array(embeddings))

    os.makedirs("embeddings", exist_ok=True)
    faiss.write_index(index, "combined_index.faiss")
    with open("combined_metadata.json", "w") as f:
        json.dump(entries, f, indent=2)

    print(f"Done. Saved {len(entries)} entries and FAISS index.")
