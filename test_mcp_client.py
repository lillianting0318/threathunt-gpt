"""
Quick local test: call the MCP tools in-memory, without Claude Desktop.
Run from the repo root:  python test_mcp_client.py
"""

import asyncio
from fastmcp import Client
from mcp_server import mcp, engine

CASES = [
    ("resolve_apt_group", {"name": "APT28"}),       # exact match
    ("resolve_apt_group", {"name": "lazarus"}),     # word-boundary match
    ("resolve_apt_group", {"name": "Fancy Bear"}),  # alias -> should NOT map to a wrong group
    ("lookup_technique", {"technique_id": "t1059"}),
    ("lookup_technique", {"technique_id": "T9999"}),  # should be found=False
    ("search_knowledge_base", {"query": "dump credentials from LSASS", "top_k": 3}),
]


async def main():
    print("FAISS metric_type:", engine.index.metric_type, "(0 = inner product, 1 = L2)")
    async with Client(mcp) as client:
        print("Tools:", [t.name for t in await client.list_tools()])
        for tool, args in CASES:
            r = await client.call_tool(tool, args)
            data = r.data if hasattr(r, "data") else r
            if isinstance(data, dict):
                print(f"\n{tool}{args} -> found={data.get('found')} group={data.get('group')} "
                      f"name={data.get('name')} error={data.get('error')}")
            else:
                print(f"\n{tool}{args} ->", [(d['title'], round(d['score'], 3)) for d in data])

    # Debug: raw semantic scores for the alias query, to tune the threshold
    print("\nRaw scores for 'Fancy Bear':")
    for r in engine.semantic_search("Fancy Bear", top_k=3):
        print(f"  {r.get('title')!r:30} {r.get('source_type'):15} score={r['score']:.3f}")


if __name__ == "__main__":
    asyncio.run(main())
