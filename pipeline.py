"""
pipeline.py — ThreatHunt-GPT Orchestrator
==========================================
兩條 pipeline：

  1. run_pipeline()           — 威脅組織查詢（CTI → TTP → Answer）
  2. run_log_triage_pipeline  — Log Triage（直接 re-export，介面統一）

OpenClaw / Multi-agent 整合：直接 import 這個模組即可取得所有 pipeline 入口。
"""

from typing import Any, Dict, List, Optional

from rag_engine import RAGEngine
from agents.cti_agent import run_cti_agent
from agents.ttp_agent import run_ttp_agent
from agents.answer_agent import run_answer_agent

# Re-export log triage pipeline so external tools only need to import pipeline.py
from log_triage_pipeline import run_log_triage_pipeline  # noqa: F401
from agents.log_processor import LogEvent, simulate_logs  # noqa: F401


# ─────────────────────────────────────────────────────────────
# Pipeline 1: Threat Group Hunt
# ─────────────────────────────────────────────────────────────

def run_pipeline(
    group_name: str,
    rag: RAGEngine,
    llm=None,
) -> Dict[str, Any]:
    """
    Full ThreatHunt pipeline for a named threat group.
    CTI Agent → TTP Agent → Answer Agent

    Returns a dict with all agent outputs, or an error dict.
    """
    matched = rag.find_group(group_name)
    if not matched:
        available = rag.get_group_names()
        return {
            "status":           "error",
            "message":          f"Group '{group_name}' not found. Try: {', '.join(available[:6])}...",
            "available_groups": available,
        }

    cti_result = run_cti_agent(matched, rag)
    if cti_result["status"] != "ok":
        return {"status": "error", "message": cti_result["summary"]}

    ttp_result = run_ttp_agent(matched, rag)
    if ttp_result["status"] not in ("ok",):
        return {"status": "error", "message": f"No TTPs found for {matched}."}

    answer_result = run_answer_agent(
        group=matched,
        cti_summary=cti_result["summary"],
        ttps=ttp_result["ttps"],
        llm=llm,
    )

    return {
        "status": "ok",
        "group":  matched,
        "cti":    cti_result,
        "ttp":    ttp_result,
        "answer": answer_result,
    }
