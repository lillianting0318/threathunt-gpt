"""
agents/ttp_agent.py — TTP Enrichment Agent
Maps group TTP IDs to full MITRE ATT&CK technique descriptions.
"""

from typing import Dict, Any, List


def run_ttp_agent(group_name: str, rag) -> Dict[str, Any]:
    """
    Retrieve and enrich TTPs for a named threat group.

    Args:
        group_name: exact group name (e.g. "APT28")
        rag: RAGEngine instance

    Returns:
        dict with group, ttp_count, ttps (enriched list)
    """
    matched = rag.find_group(group_name)
    if not matched:
        return {
            "status": "not_found",
            "group": group_name,
            "ttp_count": 0,
            "ttps": [],
        }

    ttp_ids = rag.get_ttp_ids(matched)
    if not ttp_ids:
        return {
            "status": "no_ttps",
            "group": matched,
            "ttp_count": 0,
            "ttps": [],
        }

    enriched = rag.enrich_ttps(ttp_ids)
    return {
        "status": "ok",
        "group": matched,
        "ttp_count": len(enriched),
        "ttps": enriched,
    }
