# threathunt-gpt
An LLM-powered threat hunting assistant with RAG and MITRE ATT&amp;CK integration.
# ================= README.md =================
# ThreatHunt-GPT

ThreatHunt-GPT is an interactive, LLM-powered threat hunting assistant. It combines Retrieval-Augmented Generation (RAG) with a multi-agent architecture to assist cybersecurity analysts with tasks such as:

- Querying MITRE ATT&CK techniques
- Summarizing security logs
- Classifying adversary behavior (TTPs)
- Recommending action steps based on risk

Built using Llama 3-7B, HuggingFace, FAISS, and Streamlit.

## Installation
```bash
pip install -r requirements.txt
```

## Quick Start
```bash
streamlit run ui/app.py
```

---
