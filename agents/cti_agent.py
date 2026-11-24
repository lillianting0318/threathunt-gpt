"""
agents/cti_agent.py — CTI Summary Agent
Returns threat group summary from CTI metadata.
"""

from typing import Dict, Any


def run_cti_agent(group_name: str, rag) -> Dict[str, Any]:
    """
    Retrieve CTI summary for a named threat group.

    Args:
        group_name: canonical group name, already resolved by the caller
                    (run_pipeline). This agent does not resolve aliases.
        rag: RAGEngine instance

    Returns:
        dict with group, summary, status
    """
    if group_name not in rag.get_group_names():
        return {
            "status": "not_found",
            "group": group_name,
            "summary": f"No CTI data found for '{group_name}'. "
                       f"Available groups: {', '.join(rag.get_group_names())}",
        }

    summary = rag.get_cti_summary(group_name)
    return {
        "status": "ok",
        "group": group_name,
        "summary": summary,
    }
