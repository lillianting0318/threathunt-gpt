def run_ttp_agent(query, metadata):
    group_id = query.strip().upper().replace("WHAT IS ", "").replace("WHAT TECHNIQUES DOES ", "").replace(" USE?", "").replace("?", "")
    for entry in metadata:
        if entry.get("source_type") == "cti_techniques" and group_id in entry.get("title", "").upper():
            return entry.get("text", "")
    return "No technique data found."