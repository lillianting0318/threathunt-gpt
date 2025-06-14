def threathunt_pipeline_full(query, metadata, llm, return_mode="all"):
    cti = agents/run_cti_agent(query, metadata)
    ttp = agents/run_ttp_agent(query, metadata)

    if "no cti summary" in cti.lower():
        return "[Agent] CTI summary not found."
    if "no technique data" in ttp.lower():
        return "[Agent] TTP info not found."

    answer = run_answer_agent_mistral(cti, ttp, llm)

    if return_mode == "text":
        return (
            "[CTI Agent]\\n" + cti.strip() + "\\n\\n" +
            "[TTP Agent]\\n" + ttp.strip() + "\\n\\n" +
            "[Answer Agent]\\n" + answer
        )
    else:
        return {
            "cti_agent": cti.strip(),
            "ttp_agent": ttp.strip(),
            "answer_agent": answer.strip()
        }