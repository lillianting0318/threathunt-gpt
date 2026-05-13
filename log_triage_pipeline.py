"""
log_triage_pipeline.py — Log Triage Pipeline
=============================================
整合 LogProcessor → RAG TTP 檢索 → 決策報告生成

輸出『決策報告』包含：
  - 威脅等級（High / Medium / Low）
  - 對應 MITRE TTP ID
  - SOC Analyst 處置建議
  - 可疑帳號 / IP / 主機 摘要
  - 時序攻擊鏈推斷

架構設計（OpenClaw / Multi-agent 友善）：
  - run_log_triage_pipeline() 是唯一對外入口
  - 每個步驟回傳純 dict，不依賴全域狀態
  - rag 物件由外部注入（dependency injection）
"""

from __future__ import annotations

from collections import Counter
from datetime import datetime
from typing import Any, Dict, List, Optional

from agents.log_processor import (
    LogEvent,
    TriagedLog,
    simulate_logs,
    triage_logs,
)

# ─────────────────────────────────────────────────────────────
# Threat level calculator
# ─────────────────────────────────────────────────────────────

SEVERITY_SCORE = {"High": 10, "Medium": 4, "Low": 1}

_ESCALATION_RULES = [
    # (rule_description, condition_fn, bonus_score)
    (
        "Multiple High-severity events (≥3)",
        lambda logs: sum(1 for l in logs if l.severity == "High") >= 3,
        15,
    ),
    (
        "Brute-force pattern: ≥5 failed logons (4625)",
        lambda logs: sum(1 for l in logs if l.event.event_id == 4625) >= 5,
        10,
    ),
    (
        "Log cleared (Event 1102) — active cover-up",
        lambda logs: any(l.event.event_id == 1102 for l in logs),
        20,
    ),
    (
        "Kerberoasting pattern: repeated 4769",
        lambda logs: sum(1 for l in logs if l.event.event_id == 4769) >= 3,
        15,
    ),
    (
        "Privilege escalation after lateral movement",
        lambda logs: (
            any(l.event.event_id in (4648, 4624) for l in logs)
            and any(l.event.event_id == 4672 for l in logs)
        ),
        10,
    ),
    (
        "Scheduled task or service created (persistence)",
        lambda logs: any(l.event.event_id in (4698, 7045) for l in logs),
        8,
    ),
    (
        "PowerShell script block or module logging triggered",
        lambda logs: any(l.event.event_id in (4103, 4104) for l in logs),
        8,
    ),
]


def _calculate_threat_level(triaged: List[TriagedLog]) -> Dict[str, Any]:
    """
    計算整體威脅等級，套用情境升級規則。

    Returns:
        {
            "level":           "High" | "Medium" | "Low",
            "score":           int,
            "triggered_rules": List[str],
        }
    """
    base_score = sum(SEVERITY_SCORE.get(t.severity, 0) for t in triaged)
    triggered = []

    for desc, condition, bonus in _ESCALATION_RULES:
        if condition(triaged):
            base_score += bonus
            triggered.append(desc)

    if base_score >= 30:
        level = "High"
    elif base_score >= 12:
        level = "Medium"
    else:
        level = "Low"

    return {
        "level":           level,
        "score":           base_score,
        "triggered_rules": triggered,
    }


# ─────────────────────────────────────────────────────────────
# Attack chain inference
# ─────────────────────────────────────────────────────────────

_KILL_CHAIN_MAP = {
    4625: ("Reconnaissance / Initial Access", "Credential Brute-Force"),
    4776: ("Reconnaissance / Initial Access", "NTLM Credential Probe"),
    4768: ("Credential Access",               "Kerberos AS-REQ"),
    4769: ("Credential Access",               "Kerberoasting"),
    4624: ("Lateral Movement",                "Successful Logon"),
    4648: ("Lateral Movement",                "Explicit Credential Use"),
    4688: ("Execution",                       "Process Spawn"),
    4103: ("Execution",                       "PowerShell Module"),
    4104: ("Execution",                       "PowerShell Script Block"),
    4698: ("Persistence",                     "Scheduled Task Created"),
    7045: ("Persistence",                     "Service Installed"),
    4672: ("Privilege Escalation",            "Special Privileges Assigned"),
    4719: ("Defense Evasion",                 "Audit Policy Modified"),
    1102: ("Defense Evasion",                 "Security Log Cleared"),
    4798: ("Discovery",                       "Local Group Enumeration"),
    4799: ("Discovery",                       "Security Group Enumeration"),
}


def _infer_attack_chain(triaged: List[TriagedLog]) -> List[Dict]:
    """
    按時序推斷攻擊鏈步驟。
    """
    seen = set()
    chain = []
    for t in sorted(triaged, key=lambda x: x.event.timestamp):
        eid = t.event.event_id
        if eid in _KILL_CHAIN_MAP and eid not in seen:
            phase, action = _KILL_CHAIN_MAP[eid]
            chain.append({
                "phase":     phase,
                "action":    action,
                "event_id":  eid,
                "timestamp": t.event.timestamp.isoformat(),
                "ttp_ids":   t.ttp_ids,
            })
            seen.add(eid)
    return chain


# ─────────────────────────────────────────────────────────────
# SOC recommendation engine
# ─────────────────────────────────────────────────────────────

_RECOMMENDATIONS: Dict[str, List[str]] = {
    "High": [
        "🔴 IMMEDIATE: Isolate affected hosts from network.",
        "🔴 IMMEDIATE: Reset credentials for all accounts seen in logs.",
        "🔴 Escalate to Tier 2 / Incident Response team.",
        "🔴 Preserve memory dumps and disk images for forensics.",
        "🔴 Review and revoke any new scheduled tasks or services.",
        "🔴 Check for lateral movement to other systems via 4624/4648 events.",
    ],
    "Medium": [
        "🟡 Investigate source IPs — check threat intel feeds.",
        "🟡 Review account activity for affected users in last 7 days.",
        "🟡 Enable enhanced PowerShell logging (ScriptBlock + Module).",
        "🟡 Verify scheduled tasks and services against approved baseline.",
        "🟡 Monitor for follow-on High-severity events over next 24h.",
    ],
    "Low": [
        "🟢 Log and track — no immediate action required.",
        "🟢 Verify events are within expected operational patterns.",
        "🟢 Add to weekly SOC review queue.",
    ],
}

_TTP_RECOMMENDATIONS: Dict[str, str] = {
    "T1110":     "Enable account lockout policy (≤5 attempts). Monitor 4625 bursts.",
    "T1110.001": "Enforce MFA. Block legacy auth protocols (NTLM where possible).",
    "T1110.003": "Alert on >10 failed logons across >3 accounts in 5 min (password spray).",
    "T1558.003": "Audit service accounts for weak passwords. Monitor RC4 Kerberos tickets.",
    "T1059.001": "Block encoded PowerShell execution via AppLocker / WDAC.",
    "T1059.003": "Restrict cmd.exe execution for non-admin accounts.",
    "T1053.005": "Audit schtasks — compare to approved baseline weekly.",
    "T1543.003": "Monitor new service creation. Require signed service binaries.",
    "T1070.001": "Alert immediately on 1102. Backup logs to SIEM in real-time.",
    "T1562.002": "Alert on 4719. Require change-control approval for audit policy.",
    "T1134.001": "Monitor 4648 outside expected admin workflows.",
    "T1078.002": "Review privileged account usage. Apply JIT/PAM controls.",
    "T1021.001": "Restrict RDP access. Enable NLA. Monitor for unusual source IPs.",
    "T1027":     "Deploy PowerShell Constrained Language Mode.",
}


def _generate_soc_recommendations(
    threat_level: str,
    triaged: List[TriagedLog],
) -> Dict[str, Any]:
    """
    產生分層的 SOC 處置建議。
    """
    # Base recommendations by threat level
    base = _RECOMMENDATIONS.get(threat_level, _RECOMMENDATIONS["Low"]).copy()

    # TTP-specific recommendations
    all_ttp_ids: List[str] = []
    for t in triaged:
        all_ttp_ids.extend(t.ttp_ids)
    unique_ttps = list(dict.fromkeys(all_ttp_ids))  # preserve order, deduplicate

    ttp_specific = []
    for tid in unique_ttps:
        if tid in _TTP_RECOMMENDATIONS:
            ttp_specific.append(f"[{tid}] {_TTP_RECOMMENDATIONS[tid]}")

    return {
        "base_actions":   base,
        "ttp_actions":    ttp_specific,
        "priority_ttps":  unique_ttps[:8],
    }


# ─────────────────────────────────────────────────────────────
# IOC Extractor
# ─────────────────────────────────────────────────────────────

def _extract_iocs(triaged: List[TriagedLog]) -> Dict[str, List[str]]:
    """
    從 triaged logs 提取可疑 IOC（帳號、IP、主機）。
    """
    accounts: Counter = Counter()
    ips:      Counter = Counter()
    hosts:    Counter = Counter()

    for t in triaged:
        if t.event.account and t.event.account not in ("SYSTEM", "-", ""):
            accounts[t.event.account] += 1
        if t.event.source_ip and t.event.source_ip not in ("-", "::1", "127.0.0.1"):
            ips[t.event.source_ip] += 1
        if t.event.computer:
            hosts[t.event.computer] += 1

    return {
        "suspicious_accounts": [a for a, _ in accounts.most_common(10)],
        "suspicious_ips":      [ip for ip, _ in ips.most_common(10)],
        "affected_hosts":      [h for h, _ in hosts.most_common(10)],
    }


# ─────────────────────────────────────────────────────────────
# Report builder
# ─────────────────────────────────────────────────────────────

def _build_report(
    triaged:      List[TriagedLog],
    threat_info:  Dict[str, Any],
    attack_chain: List[Dict],
    soc_recs:     Dict[str, Any],
    iocs:         Dict[str, List[str]],
    scenario:     str,
) -> Dict[str, Any]:
    """
    組裝最終決策報告。所有欄位為純 Python 型別（JSON 序列化友善）。
    """
    all_ttps = []
    seen_ids = set()
    for t in triaged:
        for tid in t.ttp_ids:
            if tid not in seen_ids:
                seen_ids.add(tid)
                mitre_url = f"https://attack.mitre.org/techniques/{tid.replace('.', '/')}/"
                # Find enriched detail
                detail = next(
                    (e for tl in triaged for e in tl.enriched_ttps if e.get("id") == tid),
                    {}
                )
                all_ttps.append({
                    "id":          tid,
                    "name":        detail.get("name", ""),
                    "description": detail.get("description", "")[:200],
                    "mitre_url":   mitre_url,
                })

    event_summary = {}
    for t in triaged:
        eid = t.event.event_id
        if eid not in event_summary:
            event_summary[eid] = {"count": 0, "title": t.title, "severity": t.severity}
        event_summary[eid]["count"] += 1

    return {
        "report_id":      f"TRIAGE-{datetime.utcnow().strftime('%Y%m%d-%H%M%S')}",
        "generated_at":   datetime.utcnow().isoformat() + "Z",
        "scenario":       scenario,
        "log_count":      len(triaged),

        # ── Threat Assessment ───────────────────────────────
        "threat_level":   threat_info["level"],
        "threat_score":   threat_info["score"],
        "escalation_rules_triggered": threat_info["triggered_rules"],

        # ── TTP Mapping ─────────────────────────────────────
        "mitre_ttps":     all_ttps,
        "event_summary":  [
            {"event_id": k, **v}
            for k, v in sorted(event_summary.items())
        ],

        # ── Attack Chain ─────────────────────────────────────
        "attack_chain":   attack_chain,

        # ── IOCs ─────────────────────────────────────────────
        "iocs":           iocs,

        # ── SOC Recommendations ──────────────────────────────
        "soc_recommendations": soc_recs,

        # ── Raw triaged logs (for downstream agents) ─────────
        "triaged_logs":   [t.to_dict() for t in triaged],
    }


# ─────────────────────────────────────────────────────────────
# Public pipeline entry point
# ─────────────────────────────────────────────────────────────

def run_log_triage_pipeline(
    scenario:         str              = "brute_force",
    custom_events:    Optional[List[LogEvent]] = None,
    rag               = None,
    return_raw_logs:  bool             = False,
) -> Dict[str, Any]:
    """
    Log Triage Pipeline — public entry point.

    Args:
        scenario:       預設情境（brute_force / lateral_movement / persistence /
                        defense_evasion / kerberoasting / full_attack）
        custom_events:  自訂 LogEvent 列表（提供時忽略 scenario）
        rag:            RAGEngine 實例（提供 MITRE 說明補充）
        return_raw_logs: 是否在結果中包含完整 raw log（預設 False）

    Returns:
        完整決策報告 dict（可直接 JSON 序列化 / 傳給其他 Agent）

    OpenClaw 整合範例：
        from log_triage_pipeline import run_log_triage_pipeline
        report = run_log_triage_pipeline(scenario="full_attack", rag=rag_instance)
        # report["threat_level"]          → "High"
        # report["soc_recommendations"]   → {...}
        # report["mitre_ttps"]            → [{"id": "T1110", ...}]
        # report["triaged_logs"]          → [{"event_id": 4625, ...}]
    """
    # Step 1: Get events
    if custom_events:
        events = custom_events
        used_scenario = "custom"
    else:
        events = simulate_logs(scenario=scenario)
        used_scenario = scenario

    # Step 2: Triage logs → TTP mapping
    triaged = triage_logs(events, rag=rag)

    # Step 3: Threat level calculation
    threat_info = _calculate_threat_level(triaged)

    # Step 4: Attack chain inference
    attack_chain = _infer_attack_chain(triaged)

    # Step 5: IOC extraction
    iocs = _extract_iocs(triaged)

    # Step 6: SOC recommendations
    soc_recs = _generate_soc_recommendations(threat_info["level"], triaged)

    # Step 7: Build final report
    report = _build_report(
        triaged=triaged,
        threat_info=threat_info,
        attack_chain=attack_chain,
        soc_recs=soc_recs,
        iocs=iocs,
        scenario=used_scenario,
    )

    if not return_raw_logs:
        report.pop("triaged_logs", None)

    return report
