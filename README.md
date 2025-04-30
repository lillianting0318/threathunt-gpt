# ThreatHunt-GPT

ThreatHunt-GPT is a prototype system for retrieval-augmented threat hunting powered by local LLMs. It integrates MITRE ATT&CK, CTI reports, and system logs into a semantic search pipeline using FAISS and a sentence transformer. The system supports natural language queries and generates context-aware responses via Ollama-hosted local models (e.g., llama3, mistral).

---

## Features
- Multi-source RAG (MITRE, CTI, logs)
- Semantic retrieval with FAISS + MiniLM
- Local LLM generation via Ollama API (streamed)
- CLI-based interactive querying

---

## Architecture Overview
```text
User Question → Sentence Embedding → FAISS Search → Prompt Construction → Ollama API → Streamed LLM Answer
```

---

## Dataset Source
The project uses three types of data:

1. **MITRE ATT&CK STIX entries**  
   - Extracted and parsed from [MITRE CTI repository](https://github.com/mitre/cti)
2. **CTI Reports**  
   - Manually collected summaries of APT groups and associated techniques
3. **System Logs**  
   - Simplified simulated logs (e.g., PowerShell usage, net.exe user creation)

> **License Note:** Some STIX data is sourced from [MITRE CTI](https://github.com/mitre/cti), licensed under [CC BY 4.0](https://github.com/mitre/cti/blob/master/LICENSE.txt). Only selected threat entries relevant to this prototype are included.

---

## Getting Started
### 1. Install Dependencies
```bash
pip install -r requirements.txt
brew install ollama
```

### 2. Run LLM Model
```bash
ollama run llama3
```

### 3. Launch the Prototype
```bash
python rag_answer_demo.py
```

---

## Example Usage
```text
Enter your question (or 'exit'): What techniques does APT29 use?

=== Ollama Answer ===
APT29 is known for spearphishing, credential theft, and malware deployment.
```

---

## Project Structure
```
core/                  # Main logic and retriever script
embeddings/            # FAISS index + metadata JSON
data/                  # Selected MITRE + CTI threat data
logs/                  # Simulated log entries
threat_intel_examples/ # APT group summaries
```

---

## Credits
Developed as part of an academic project for Applying Large Language Models in Cybersecurity Systems
