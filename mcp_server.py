"""
ThreatHunt-GPT MCP server.

Exposes ThreatHunt-GPT's MITRE ATT&CK lookup and APT group resolution
as MCP tools, so any MCP client (e.g. Claude Desktop) can call them.

Run from the ThreatHunt-GPT repo root:
    python mcp_server.py

IMPORTANT (stdio transport):
    stdout is reserved for MCP protocol messages. Any print() to stdout
    will break the connection. Log to stderr instead (see log() below).
"""

import sys
from fastmcp import FastMCP
from rag_engine import RAGEngine, ICS_TECHNIQUES


def log(msg: str) -> None:
    """Write logs to stderr so they don't corrupt the MCP stdio stream."""
    print(msg, file=sys.stderr, flush=True)


mcp = FastMCP("ThreatHunt")

# Load FAISS index + MITRE data once at startup, not on every tool call.
log("Loading RAGEngine...")
engine = RAGEngine()
log("RAGEngine ready.")


@mcp.tool
def lookup_technique(technique_id: str) -> dict:
    """Look up a MITRE ATT&CK technique by its ID (e.g. T1059, T1566.001, T0855).

    Returns the technique name, domain, and description.
    Use this when the user mentions a specific technique ID.
    """
    tid = technique_id.strip().upper()
    # Only report found=True if the ID really exists (enrich_ttps always
    # returns a placeholder, so check the lookups directly first).
    if tid not in engine.mitre_lookup and tid not in ICS_TECHNIQUES:
        return {"found": False, "error": f"Technique {tid} not found in ATT&CK data"}
    return {"found": True, **engine.enrich_ttps([tid])[0]}


@mcp.tool
def resolve_apt_group(name: str) -> dict:
    """Resolve an APT group name (e.g. 'APT28', 'Lazarus') to its canonical
    MITRE ATT&CK group, CTI summary, and the techniques it uses.

    Uses a layered lookup: exact match -> word-boundary match -> FAISS semantic
    fallback (with a distance threshold). Use this when the user asks about a
    threat actor.
    """
    group = engine.find_group(name)  # returns the canonical group name (str) or None
    if group is None:
        return {"found": False, "query": name,
                "error": f"No ATT&CK group confidently matched '{name}'"}
    return {"found": True, "query": name, **engine.full_lookup(group)}


@mcp.tool
def search_knowledge_base(query: str, top_k: int = 5) -> list[dict]:
    """Semantic search over the ThreatHunt knowledge base
    (threat-group CTI summaries + MITRE ATT&CK technique descriptions).

    Returns the top_k most relevant entries with their FAISS distance score.
    """
    results = engine.semantic_search(query, top_k=top_k)
    return [
        {
            "title": r.get("title", ""),
            "source_type": r.get("source_type", ""),
            "score": float(r.get("score", 0.0)),
            "text": r.get("text", "")[:500],
        }
        for r in results
    ]


if __name__ == "__main__":
    mcp.run()  # default transport: stdio (what Claude Desktop uses)
