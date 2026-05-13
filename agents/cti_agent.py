"""
agents/cti_agent.py — CTI Summary Agent
Returns threat group summary from CTI metadata.
"""

from typing import Dict, Any


def run_cti_agent(group_name: str, rag) -> Dict[str, Any]:
    """
    Retrieve CTI summary for a named threat group.

    Args:
        group_name: exact group name (e.g. "APT28")
        rag: RAGEngine instance

    Returns:
        dict with group, summary, status
    """
    matched = rag.find_group(group_name)
    if not matched:
        return {
            "status": "not_found",
            "group": group_name,
            "summary": f"No CTI data found for '{group_name}'. "
                       f"Available groups: {', '.join(rag.get_group_names())}",
        }

    summary = rag.get_cti_summary(matched)
    return {
        "status": "ok",
        "group": matched,
        "summary": summary,
    }
