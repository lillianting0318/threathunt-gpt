"""
agents/answer_agent.py — Answer / Generation Agent
Using Groq API generates threat intelligence summaries (model controlled by TH_LLM_MODEL, defaulting to openai/gpt-oss-120b)

Set your Groq API key in your shell environment:
  export GROQ_API_KEY="gsk_xxxxxxxxxxxx"
  or in a .env file in the project root:
  GROQ_API_KEY=gsk_xxxxxxxxxxxx

apply free key: https://console.groq.com
"""

import os
import re
from typing import Dict, Any, List

# ── auto-load .env ──────────────────────────────────────
try:
    from dotenv import load_dotenv
    load_dotenv()
except ImportError:
    pass
# ── LLM model (override with TH_LLM_MODEL in .env) ────
LLM_MODEL = os.environ.get("TH_LLM_MODEL", "openai/gpt-oss-120b")

# ── Groq client（lazy init）───────────────────────────
_groq_client = None

def _get_groq_client():
    global _groq_client
    if _groq_client is None:
        try:
            from groq import Groq
            api_key = os.environ.get("GROQ_API_KEY", "")
            if not api_key:
                return None
            _groq_client = Groq(api_key=api_key)
        except ImportError:
            return None
    return _groq_client


# ---------------------------------------------------------------------------
# Call Groq LLM
# ---------------------------------------------------------------------------
def _call_llm(prompt: str) -> str:
    client = _get_groq_client()

    if client is None:
        api_key = os.environ.get("GROQ_API_KEY", "")
        if not api_key:
            return (
                "⚠ Groq API key 未設定。\n\n"
                "請執行：\n"
                "  export GROQ_API_KEY='gsk_你的金鑰'\n\n"
                "或在專案根目錄建立 .env 檔：\n"
                "  GROQ_API_KEY=gsk_你的金鑰\n\n"
                "申請免費 key：https://console.groq.com"
            )
        return "⚠ 請執行 pip install groq 安裝 Groq 套件"

    try:
        response = client.chat.completions.create(
            model=LLM_MODEL,
            messages=[
                {
                    "role": "system",
                    "content": (
                        "You are an expert cybersecurity threat intelligence analyst "
                        "specializing in APT group behavior, MITRE ATT&CK mapping, "
                        "and threat hunting. Be precise, technical, and concise."
                    ),
                },
                {"role": "user", "content": prompt},
            ],
            temperature=0.3,
            max_tokens=2048,
            extra_body={"reasoning_effort": "low"},
        )
        return (response.choices[0].message.content or "").strip()
    except Exception as e:
        return f"⚠ Groq API 錯誤：{e}"


# ---------------------------------------------------------------------------
# YARA rule generator
# ---------------------------------------------------------------------------
def _generate_yara(group: str, ttps: List[Dict]) -> str:
    ttp_ids   = [t["id"]   for t in ttps]
    ttp_names = [t["name"] for t in ttps[:6]]

    keyword_map = {
        "PowerShell":     '$ps      = "powershell" nocase',
        "Command":        '$cmd     = "cmd.exe" nocase',
        "Regsvr32":       '$reg32   = "regsvr32" nocase',
        "rundll32":       '$rdll    = "rundll32" nocase',
        "Scheduled Task": '$schtask = "schtasks" nocase',
        "Registry":       '$reg_key = "HKCU\\\\Software\\\\Microsoft" nocase',
        "Lateral":        '$lateral = "net use" nocase',
        "Credential":     '$cred    = "mimikatz" nocase',
        "Phishing":       '$macro   = "AutoOpen" nocase',
        "Obfuscat":       '$b64     = /[A-Za-z0-9+\\/]{50,}={0,2}/',
        "Screen":         '$scrshot = "screenshot" nocase',
        "Firmware":       '$fw      = "firmware" nocase',
        "Valid Account":  '$auth    = "net logon" nocase',
    }

    string_hints = []
    for name in ttp_names:
        for kw, pattern in keyword_map.items():
            if kw.lower() in name.lower() and pattern not in string_hints:
                string_hints.append(f"        {pattern}")

    if not string_hints:
        string_hints = ['        $generic = "suspicious_indicator" nocase']

    tag = re.sub(r"[^a-zA-Z0-9_]", "_", group)
    strings_block = "\n".join(string_hints)

    return f"""rule ThreatHunt_{tag} {{
    meta:
        description = "Hunt rule for {group} indicators"
        group       = "{group}"
        ttps        = "{', '.join(ttp_ids[:8])}"
        author      = "ThreatHunt-GPT"
        confidence  = "medium"
        reference   = "https://attack.mitre.org"

    strings:
{strings_block}

    condition:
        any of them
}}"""


# ---------------------------------------------------------------------------
# KQL query generator
# ---------------------------------------------------------------------------
def _generate_kql(group: str, ttps: List[Dict]) -> str:
    ttp_ids = [t["id"] for t in ttps]
    return "\n".join([
        f"// ThreatHunt-GPT — KQL Hunt Queries for {group}",
        f"// TTPs: {', '.join(ttp_ids[:10])}",
        "// Target: Microsoft Sentinel / Defender for Endpoint",
        "",
        "// ─── Process Execution ───────────────────────────────",
        "DeviceProcessEvents",
        "| where Timestamp > ago(7d)",
        '| where FileName in~ ("powershell.exe","cmd.exe","regsvr32.exe","rundll32.exe","mshta.exe","wscript.exe")',
        '| where InitiatingProcessFileName !in~ ("explorer.exe","svchost.exe","services.exe")',
        "| project Timestamp, DeviceName, AccountName, FileName, ProcessCommandLine",
        "| sort by Timestamp desc",
        "",
        "// ─── Suspicious Network Connections ──────────────────",
        "DeviceNetworkEvents",
        "| where Timestamp > ago(7d)",
        "| where RemotePort in (80, 443, 8080, 8443, 4444, 1337)",
        '| where InitiatingProcessFileName in~ ("powershell.exe","rundll32.exe","mshta.exe")',
        "| summarize count(), dcount(RemoteIP) by DeviceName, InitiatingProcessFileName, RemoteUrl",
        "| sort by count_ desc",
        "",
        "// ─── Registry Persistence ─────────────────────────────",
        "DeviceRegistryEvents",
        "| where Timestamp > ago(7d)",
        '| where RegistryKey has_any ("Run","RunOnce","Services","Winlogon")',
        "| where ActionType in ('RegistryValueSet','RegistryKeyCreated')",
        "| project Timestamp, DeviceName, RegistryKey, RegistryValueName, RegistryValueData",
        "",
        "// ─── Credential Access ────────────────────────────────",
        "DeviceProcessEvents",
        "| where Timestamp > ago(7d)",
        '| where ProcessCommandLine has_any ("sekurlsa","mimikatz","procdump","ntds.dit","lsass")',
        "| project Timestamp, DeviceName, AccountName, ProcessCommandLine",
    ])


# ---------------------------------------------------------------------------
# SPL query generator
# ---------------------------------------------------------------------------
def _generate_spl(group: str, ttps: List[Dict]) -> str:
    ttp_ids = [t["id"] for t in ttps]
    return "\n".join([
        f'| comment "ThreatHunt-GPT — SPL Hunt for {group}"',
        f'| comment "TTPs: {", ".join(ttp_ids[:10])}"',
        "",
        "| tstats count min(_time) as firstTime max(_time) as lastTime",
        "  from datamodel=Endpoint.Processes",
        '  where Processes.process_name IN ("powershell.exe","cmd.exe","regsvr32.exe","rundll32.exe","mshta.exe")',
        '  AND Processes.parent_process_name NOT IN ("explorer.exe","svchost.exe")',
        "  by Processes.dest Processes.user Processes.process_name Processes.process Processes.parent_process_name",
        "| rename Processes.* as *",
        f'| eval threat_group="{group}"',
        "| table firstTime lastTime dest user process_name process parent_process_name threat_group",
        "| sort - lastTime",
        "",
        '| comment "─── Network Connections ───"',
        "| tstats count min(_time) as firstTime max(_time) as lastTime",
        "  from datamodel=Network_Traffic.All_Traffic",
        "  where All_Traffic.dest_port IN (80, 443, 8080, 4444, 1337)",
        "  by All_Traffic.src_ip All_Traffic.dest_ip All_Traffic.dest_port All_Traffic.app",
        "| rename All_Traffic.* as *",
        "| sort - count",
    ])


# ---------------------------------------------------------------------------
# Hunt summary via Groq
# ---------------------------------------------------------------------------
# How many of the group's techniques are shown to the LLM. The faithfulness
# eval (eval/run_faithfulness.py) reads this so it checks the summary against
# exactly what the model was given.
SUMMARY_TTP_LIMIT = 10


def _generate_summary(group: str, cti_summary: str, ttps: List[Dict]) -> str:
    ttp_block = "\n".join(
        f"  - {t['id']} ({t['name']}): {t['description'][:120]}"
        for t in ttps[:SUMMARY_TTP_LIMIT]
    )
    prompt = f"""You are a senior threat intelligence analyst writing a threat hunt brief.

Threat Group: {group}

CTI Summary:
{cti_summary}

MITRE ATT&CK Techniques ({len(ttps)} total, top {SUMMARY_TTP_LIMIT}):
{ttp_block}

Write a concise threat hunt summary covering:
1. Group profile (1-2 sentences)
2. Primary attack methods and kill chain (2-3 sentences)
3. Top detection priorities for defenders (2-3 sentences)
4. Recommended hunt hypothesis (1 sentence)

Be specific, technical, and actionable. Plain paragraphs only, no bullet points."""

    return _call_llm(prompt)


# ---------------------------------------------------------------------------
# Main entry point
# ---------------------------------------------------------------------------
def run_answer_agent(
    group: str,
    cti_summary: str,
    ttps: List[Dict],
    llm=None,
) -> Dict[str, Any]:
    return {
        "status":       "ok",
        "group":        group,
        "hunt_summary": _generate_summary(group, cti_summary, ttps),
        "yara_rule":    _generate_yara(group, ttps),
        "kql_query":    _generate_kql(group, ttps),
        "spl_query":    _generate_spl(group, ttps),
    }
