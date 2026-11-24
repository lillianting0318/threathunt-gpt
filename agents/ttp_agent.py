"""
agents/ttp_agent.py — TTP Enrichment Agent
Maps group TTP IDs to full MITRE ATT&CK technique descriptions.
"""

from typing import Dict, Any, List


def run_ttp_agent(group_name: str, rag) -> Dict[str, Any]:
    """
    Retrieve and enrich TTPs for a named threat group.

    Args:
        group_name: canonical group name, already resolved by the caller
                    (run_pipeline). This agent does not resolve aliases.
        rag: RAGEngine instance

    Returns:
        dict with group, ttp_count, ttps (enriched list)
    """
    if group_name not in rag.get_group_names():
        return {
            "status": "not_found",
            "group": group_name,
            "ttp_count": 0,
            "ttps": [],
        }

    ttp_ids = rag.get_ttp_ids(group_name)
    if not ttp_ids:
        return {
            "status": "no_ttps",
            "group": group_name,
            "ttp_count": 0,
            "ttps": [],
        }

    enriched = rag.enrich_ttps(ttp_ids)
    return {
        "status": "ok",
        "group": group_name,
        "ttp_count": len(enriched),
        "ttps": enriched,
    }
