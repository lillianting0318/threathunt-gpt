# ThreatHunt-GPT

> MITRE ATT&CK® Threat Hunting Platform — 3-Agent RAG Pipeline + Log Triage Agent

![Python](https://img.shields.io/badge/Python-3.11-3776AB?style=flat&logo=python&logoColor=white)
![Streamlit](https://img.shields.io/badge/Streamlit-1.55-FF4B4B?style=flat&logo=streamlit&logoColor=white)
![MITRE ATT&CK](https://img.shields.io/badge/MITRE_ATT%26CK®-Enterprise_+_ICS-red?style=flat)
![LLM](https://img.shields.io/badge/LLM-Groq_llama--3.3--70b-F55036?style=flat)

---

## Table of Contents

- [Overview](#overview)
- [Architecture](#architecture)
- [Quick Start](#quick-start)
- [Groq API Key Setup](#groq-api-key-setup)
- [How to Use](#how-to-use)
- [Log Triage Agent](#log-triage-agent)
- [Multi-Group Comparison](#multi-group-comparison)
- [Extending CTI Data](#extending-cti-data)
- [Swapping the LLM](#swapping-the-llm)
- [OpenClaw / Multi-Agent Integration](#openclaw--multi-agent-integration)
- [Project Structure](#project-structure)
- [Supported Threat Groups](#supported-threat-groups)

---

## Overview

ThreatHunt-GPT is a cybersecurity threat intelligence platform that combines RAG (Retrieval-Augmented Generation) with MITRE ATT&CK® to help SOC analysts and threat hunters quickly identify, analyze, and respond to threats.

| Feature | Description |
|---|---|
| **Threat Group Query** | Enter any APT name to retrieve CTI summaries and mapped MITRE TTPs |
| **YARA Rule Generation** | Auto-generate deployable YARA detection rules by tactic category |
| **KQL Queries** | Ready-to-use Microsoft Sentinel / Defender for Endpoint hunting queries |
| **SPL Queries** | Splunk Enterprise Security hunting queries |
| **AI Hunt Summary** | Groq `llama-3.3-70b` generates structured threat assessments |
| **Multi-Group Comparison** | Side-by-side TTP overlap analysis across multiple APT groups |
| **Log Triage Agent** | Analyze Windows Event Logs and produce threat-level decision reports |

---

## Architecture

```
┌─────────────────────────────────────────────────────────┐
│                   Streamlit UI (app.py)                  │
└────────────┬──────────────────────────┬─────────────────┘
             │                          │
             ▼                          ▼
┌────────────────────┐      ┌───────────────────────────┐
│    pipeline.py     │      │  log_triage_pipeline.py   │
│  (Threat Hunt)     │      │  (Log Triage Agent)       │
└──┬──────┬──────┬───┘      └──┬────────────────────────┘
   │      │      │             │
   ▼      ▼      ▼             ▼
 CTI    TTP   Answer       LogProcessor
Agent  Agent  Agent      (log_processor.py)
   │      │      │             │
   └──────┴──────┘             │
             │                 ▼
             ▼           MITRE TTP Enrichment
        RAGEngine
       (rag_engine.py)
             │
     ┌───────┴────────┐
     │                │
  FAISS Index    MITRE ATT&CK
  (vector search)  823 techniques
                  Enterprise + ICS
```

### 3-Agent Threat Hunt Pipeline

```
User Query
    │
    ▼
[Agent 1 — CTI Agent]      Retrieves threat group summary from CTI knowledge base
    │                      Uses exact match → word-boundary regex → FAISS semantic search
    ▼
[Agent 2 — TTP Agent]      Maps group to MITRE technique IDs
    │                      Enriches each TTP with full name + description from ATT&CK
    ▼
[Agent 3 — Answer Agent]   Calls Groq llama-3.3-70b for threat assessment
    │                      Generates YARA rules, KQL queries, SPL queries
    ▼
Output: CTI Summary · TTP Matrix · YARA · KQL · SPL
```

### Log Triage Pipeline

```
Select Scenario
    │
    ▼
simulate_logs()            Generates Windows Event Logs (4625, 4688, 1102, ...)
    │
    ▼
LogProcessor               Maps each Event ID → MITRE TTP
    │                      Enriches TTPs via RAGEngine
    ▼
_calculate_threat_level()  Applies 7 escalation rules → High / Medium / Low
    │
    ▼
_infer_attack_chain()      Reconstructs kill chain in chronological order
    │
    ▼
_generate_soc_recs()       Produces tiered SOC recommendations + TTP-specific controls
    │
    ▼
Decision Report (dict)     Fully JSON-serializable, ready for downstream agents
```

---

## Quick Start

### Requirements

- Python 3.11+
- macOS / Linux / Windows
- ~500MB disk (model weights cached on first run)

### Installation

```bash
# Clone or unzip the project
cd threathunt-gpt

# Install dependencies
pip install -r requirements.txt

# Set your Groq API key (see next section)
export GROQ_API_KEY="gsk_your_key_here"

# Launch
streamlit run app.py
```

Open `http://localhost:8501` in your browser.

---

## Groq API Key Setup

**Get a free key:** [https://console.groq.com](https://console.groq.com) — no credit card required.

**Option A — .env file (recommended)**

Create a `.env` file in the project root:

```
GROQ_API_KEY=gsk_your_key_here
```

**Option B — Environment variable**

```bash
export GROQ_API_KEY="gsk_your_key_here"
```

If no key is set, the AI Hunt Summary tab will display setup instructions instead of crashing.

---

## How to Use

### Threat Group Query

1. Click any group in the **AVAILABLE GROUPS** sidebar list, or type a name in the search bar
2. Click **⟩ HUNT**
3. Results appear across five tabs:

| Tab | Content |
|---|---|
| CTI Summary | Threat group profile + AI-generated hunt assessment |
| TTP Matrix | All mapped MITRE techniques with descriptions and links |
| YARA Rules | Detection rules generated from tactic templates |
| KQL Queries | Microsoft Sentinel hunting queries per tactic |
| SPL Queries | Splunk ES hunting queries per tactic |

### Search Tips

- Exact name: `APT28`
- Partial name: `lazarus` → matches `Lazarus Group`
- Natural language: `What techniques does FIN7 use?`
- The matching engine uses **word-boundary regex** to prevent APT1 from matching APT12

---

## Log Triage Agent

Located in the sidebar under **◈ LOG TRIAGE**.

### Available Scenarios

| Scenario | Event IDs Simulated | Description |
|---|---|---|
| `brute_force` | 4625 ×5, 4624, 4672 | Credential brute-force followed by successful logon |
| `lateral_movement` | 4624, 4648, 4672, 4688 | Network logon with explicit credentials and process spawn |
| `persistence` | 4698, 7045, 4688 | Scheduled task and service installation |
| `defense_evasion` | 1102, 4719, 4688, 4103 | Log cleared + audit policy change + PowerShell |
| `kerberoasting` | 4768, 4769 ×3, 4776 | Repeated Kerberos service ticket requests |
| `full_attack` | All of the above | Complete multi-stage attack chain |

### Output Tabs

| Tab | Content |
|---|---|
| SOC Report | Threat level banner + escalation rules triggered + tiered action items |
| Attack Chain | Chronological kill chain reconstruction |
| TTP Mapping | All MITRE techniques identified with descriptions |
| IOC Summary | Suspicious accounts, source IPs, affected hosts |
| Event Log | Event ID breakdown with severity and occurrence count |

### Threat Level Scoring

| Rule | Score Bonus |
|---|---|
| Security log cleared (Event 1102) | +20 |
| 3+ High-severity events | +15 |
| Kerberoasting pattern (≥3 × Event 4769) | +15 |
| Brute-force pattern (≥5 × Event 4625) | +10 |
| Privilege escalation after lateral movement | +10 |
| Persistence mechanism detected | +8 |
| PowerShell script block logging triggered | +8 |

Final score ≥ 30 → **High** · ≥ 12 → **Medium** · < 12 → **Low**

### Using Real Log Data

Replace `simulate_logs()` with your own parser:

```python
from agents.log_processor import LogEvent, triage_logs
from datetime import datetime

# Parse from EVTX, SIEM API, or any source
events = [
    LogEvent(
        event_id=4625,
        timestamp=datetime.utcnow(),
        computer="WIN-DC01",
        account="jsmith",
        source_ip="10.0.0.55",
        description="Failed logon attempt",
    ),
    # ... more events
]

triaged = triage_logs(events, rag=rag_instance)
```

---

## Multi-Group Comparison

1. Click a group in the sidebar to select it
2. Click **+ ADD** to add it to the comparison list
3. Repeat for additional groups (2 or more required)
4. Click **COMPARE**

### Comparison Tabs

| Tab | Content |
|---|---|
| TTP Overlap | Techniques shared across all groups (yellow) + unique techniques per group |
| CTI Summaries | Side-by-side intelligence summaries |
| TTP Breakdown | Full technique lists per group, shared TTPs marked with ⚠ |

For two-group comparison, a three-column Venn-style view shows: Only Group A · Shared · Only Group B.

---

## Extending CTI Data

Add new threat groups by creating JSON files in `threat_intel_examples/`:

```json
{
    "title": "APT99",
    "summary": "APT99 is a financially motivated group targeting...",
    "techniques": ["T1059.001", "T1071.001", "T1566.001", "T1486"]
}
```

Then rebuild the FAISS index:

```bash
python faiss_builder.py
```

The new group will appear automatically in the sidebar.

---

## Swapping the LLM

The Answer Agent is in `agents/answer_agent.py`. Replace `_call_llm()` with any LLM:

### Ollama (local, fully free)

```bash
ollama pull mistral
```

```python
import requests

def _call_llm(prompt: str) -> str:
    r = requests.post("http://localhost:11434/api/generate", json={
        "model": "mistral",
        "prompt": prompt,
        "stream": False,
    })
    return r.json()["response"]
```

### OpenAI

```python
from openai import OpenAI
client = OpenAI(api_key="sk-...")

def _call_llm(prompt: str) -> str:
    r = client.chat.completions.create(
        model="gpt-4o-mini",
        messages=[{"role": "user", "content": prompt}],
        max_tokens=600,
    )
    return r.choices[0].message.content
```

### Anthropic Claude

```python
import anthropic
client = anthropic.Anthropic(api_key="sk-ant-...")

def _call_llm(prompt: str) -> str:
    r = client.messages.create(
        model="claude-sonnet-4-5",
        max_tokens=600,
        messages=[{"role": "user", "content": prompt}],
    )
    return r.content[0].text
```

---

## OpenClaw / Multi-Agent Integration

All pipeline outputs are plain Python dicts — fully JSON-serializable and framework-agnostic.

```python
# Import only what you need
from pipeline import run_pipeline, run_log_triage_pipeline
from agents.log_processor import LogEvent, triage_logs
from rag_engine import RAGEngine

rag = RAGEngine(
    faiss_path="combined_index.faiss",
    metadata_path="combined_metadata.json",
    mitre_path="combined_mitre.json",
)

# --- Threat Hunt ---
result = run_pipeline(group_name="APT28", rag=rag)
# result["threat_level"]              → "High"
# result["cti"]["summary"]            → str
# result["ttp"]["ttps"]               → List[Dict]
# result["answer"]["yara_rule"]       → str
# result["answer"]["kql_query"]       → str
# result["answer"]["hunt_summary"]    → str

# --- Log Triage ---
report = run_log_triage_pipeline(scenario="full_attack", rag=rag)
# report["threat_level"]                      → "High"
# report["escalation_rules_triggered"]        → List[str]
# report["attack_chain"]                      → List[Dict]
# report["soc_recommendations"]["base_actions"] → List[str]
# report["mitre_ttps"]                        → List[Dict]
# report["iocs"]                              → Dict

# --- Custom Log Events ---
from agents.log_processor import simulate_logs
events = simulate_logs(scenario="kerberoasting")
triaged = triage_logs(events, rag=rag)
for t in triaged:
    print(t.to_dict())  # JSON-serializable
```

### Stable Interfaces (safe to depend on)

| Function | Location | Signature |
|---|---|---|
| `run_pipeline()` | `pipeline.py` | `(group_name, rag, llm=None) → Dict` |
| `run_log_triage_pipeline()` | `pipeline.py` | `(scenario, custom_events, rag) → Dict` |
| `triage_logs()` | `agents/log_processor.py` | `(events, rag=None) → List[TriagedLog]` |
| `simulate_logs()` | `agents/log_processor.py` | `(scenario, count, custom_event_ids) → List[LogEvent]` |
| `rag.find_group()` | `rag_engine.py` | `(query) → Optional[str]` |
| `rag.enrich_ttps()` | `rag_engine.py` | `(ttp_ids) → List[Dict]` |

---

## Project Structure

```
threathunt-gpt/
│
├── app.py                      # Streamlit UI — all pages and routing
├── pipeline.py                 # Pipeline orchestrator (re-exports all entry points)
├── rag_engine.py               # RAGEngine class — FAISS search + MITRE enrichment
├── log_triage_pipeline.py      # Log Triage pipeline — scoring, chain, report builder
│
├── agents/
│   ├── __init__.py
│   ├── cti_agent.py            # Agent 1 — CTI summary retrieval
│   ├── ttp_agent.py            # Agent 2 — TTP enrichment
│   ├── answer_agent.py         # Agent 3 — Groq LLM + YARA/KQL/SPL generation
│   └── log_processor.py        # Log Triage Agent — Event ID → TTP mapping
│
├── combined_index.faiss         # FAISS vector index (semantic search)
├── combined_metadata.json       # CTI knowledge base (APT summaries + TTP lists)
├── combined_mitre.json          # MITRE ATT&CK techniques (823 Enterprise + ICS)
│
├── requirements.txt
└── README.md
```

---

## Supported Threat Groups

24 threat groups currently in the knowledge base:

| Group | Type | Origin |
|---|---|---|
| APT1 | Nation-state | China (PLA Unit 61398) |
| APT3 | Nation-state | China (MSS) |
| APT12 | Nation-state | China |
| APT16 | Nation-state | China |
| APT17 | Nation-state | China |
| APT18 | Nation-state | China |
| APT19 | Nation-state | China |
| APT28 | Nation-state | Russia (GRU) |
| APT29 | Nation-state | Russia (SVR) |
| APT30 | Nation-state | China |
| APT32 | Nation-state | Vietnam |
| APT33 | Nation-state | Iran |
| APT-C-23 | Nation-state | Middle East |
| APT-C-36 | Nation-state | South America |
| ALLANITE | Nation-state | Russia (suspected) |
| Agrius | Nation-state | Iran (MOIS) |
| Ajax Security Team | Nation-state | Iran |
| Akira | Cybercrime | Unknown |
| Andariel | Nation-state | North Korea (Lazarus sub-group) |
| Aoqin Dragon | Nation-state | China (suspected) |
| Cobalt Group | Cybercrime | Unknown |
| FIN7 | Cybercrime | Unknown |
| Lazarus Group | Nation-state | North Korea |
| admin@338 | Nation-state | China |

To add more groups, see [Extending CTI Data](#extending-cti-data).

---

## Dependencies

| Package | Purpose |
|---|---|
| `streamlit` | Web UI |
| `faiss-cpu` | Vector similarity search |
| `sentence-transformers` | Text embedding model (all-MiniLM-L6-v2) |
| `groq` | LLM API client |
| `python-dotenv` | Environment variable loading |
| `numpy` | Vector operations |

---

## Known Limitations

- **ICS techniques**: T0xxx techniques are covered by a hardcoded lookup table (93 techniques). For full ICS coverage, download the MITRE ICS ATT&CK STIX bundle and rebuild the index.
- **CTI data**: The knowledge base contains 24 groups. Real-world deployments should integrate with MITRE ATT&CK TAXII feeds or commercial CTI platforms.
- **Log simulation**: The Log Triage Agent generates synthetic logs. For production use, replace `simulate_logs()` with a real EVTX parser or SIEM API connector.
- **YARA/KQL/SPL rules**: Generated from tactic templates. Always review and tune before deploying to production environments.

---

## License

For research and educational purposes. MITRE ATT&CK® is a registered trademark of The MITRE Corporation.
