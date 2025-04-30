import json
import faiss
from sentence_transformers import SentenceTransformer
import numpy as np
import os

# 初始化資料
entries = []

# 讀取 MITRE ATT&CK 技術資料
def load_mitre(file_path):
    with open(file_path, 'r') as f:
        data = json.load(f)

    # 如果是單筆 JSON（非 list），包成 list
    if isinstance(data, dict):
        data = [data]

    for t in data:
        entries.append({
            "source_type": t.get('type', 'unknown'),  # 這裡會是 malware, group, tool, etc
            "id": t.get('id', ''),
            "text": t.get('description', '')
        })

# 讀取 CTI 報告
def load_cti(folder_path):
    for filename in os.listdir(folder_path):
        if filename.endswith(".json"):
            with open(os.path.join(folder_path, filename), 'r') as f:
                cti = json.load(f)
                entries.append({
                "source_type": "cti_summary",
                "title": cti.get('title', ''),
                "text": cti.get('summary', '')
                })
            if 'techniques' in cti and isinstance(cti['techniques'], list):
                technique_ids = [t.get('id', '') for t in cti['techniques'] if 'id' in t]
                text = " ".join(technique_ids)
                entries.append({
                    "source_type": "cti_techniques",
                    "title": cti.get('title', ''),
                    "text": text
                })
# 讀取 LOGS
def load_logs(folder_path):
    for filename in os.listdir(folder_path):
        if filename.endswith(".json"):
            with open(os.path.join(folder_path, filename), 'r') as f:
                log = json.load(f)
            text_parts = []
            # 只處理 process_name、user、timestamp 三個欄位
            if 'process_name' in log:
                text_parts.append(log['process_name'])
            if 'user' in log:
                text_parts.append(f"user: {log['user']}")
            if 'timestamp' in log:
                text_parts.append(f"time: {log['timestamp']}")
            # 只要三者有其一才加入
            if text_parts:
                entries.append({
                    "source_type": "log",
                    "event_id": log['event_id'],
                    "text": " | ".join(text_parts)
                })

# 執行流程
if __name__ == "__main__":
    # 初始化
    embed_model = SentenceTransformer('all-MiniLM-L6-v2')
    
    # 讀取所有資料
    load_mitre('data/combined_mitre.json')
    load_cti('data/threat_intel_examples')
    load_logs('data/logs')

    # 轉成向量
    descriptions = [e['text'] for e in entries]
    embeddings = embed_model.encode(descriptions, show_progress_bar=True)

    # 建立 FAISS 索引
    dimension = embeddings.shape[1]
    index = faiss.IndexFlatL2(dimension)
    index.add(np.array(embeddings))

    # 保存 FAISS 索引
    if not os.path.exists('embeddings'):
        os.makedirs('embeddings')

    faiss.write_index(index, 'embeddings/combined_index.faiss')

    # 同時存一份 metadata (方便檢索時知道是哪個entry)
    with open('embeddings/combined_metadata.json', 'w') as f:
        json.dump(entries, f, indent=2)

    print(f"FAISS index built with {len(entries)} entries, saved to 'embeddings/combined_index.faiss'")