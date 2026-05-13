"""
agents/log_processor.py — Log Triage Agent
============================================
接收 Windows Event Logs，將每條 log 映射到 MITRE TTP，
輸出結構化的 triaged log 清單供下游 pipeline 使用。

設計原則（方便接入 OpenClaw / Multi-agent 框架）：
  - LogEvent       : 單條 log 的 dataclass（純資料，無副作用）
  - LogProcessor   : 解析器，可替換成真實 log 來源（EVTX / Syslog / API）
  - triage_logs()  : 主入口，回傳 List[TriagedLog]，介面穩定

外部整合範例（OpenClaw）：
  from agents.log_processor import triage_logs, LogEvent
  events = [LogEvent(event_id=4625, ...)]
  results = triage_logs(events, rag)
"""

from __future__ import annotations

import random
import re
from dataclasses import dataclass, field
from datetime import datetime, timedelta
from typing import Any, Dict, List, Optional

# ─────────────────────────────────────────────────────────────
# Event ID → MITRE TTP 映射表
# 來源：MITRE ATT&CK + Microsoft Security Event documentation
# ─────────────────────────────────────────────────────────────
EVENT_TTP_MAP: Dict[int, Dict[str, Any]] = {
    # ── Credential Access ──────────────────────────────────
    4625: {
        "ttp_ids":   ["T1110", "T1110.001", "T1110.003"],
        "tactic":    "Credential Access",
        "severity":  "Medium",
        "title":     "Failed Logon",
        "risk_note": "Repeated failures may indicate brute-force or password spray.",
    },
    4648: {
        "ttp_ids":   ["T1134.001", "T1550.002"],
        "tactic":    "Defense Evasion / Lateral Movement",
        "severity":  "High",
        "title":     "Explicit Credential Logon",
        "risk_note": "Logon using explicit credentials — possible Pass-the-Hash or credential misuse.",
    },
    4768: {
        "ttp_ids":   ["T1558", "T1558.003"],
        "tactic":    "Credential Access",
        "severity":  "Medium",
        "title":     "Kerberos TGT Requested",
        "risk_note": "Abnormal TGT requests may indicate Kerberoasting or AS-REP Roasting.",
    },
    4769: {
        "ttp_ids":   ["T1558.003"],
        "tactic":    "Credential Access",
        "severity":  "High",
        "title":     "Kerberos Service Ticket Requested",
        "risk_note": "RC4 encryption in service tickets is a classic Kerberoasting indicator.",
    },
    4776: {
        "ttp_ids":   ["T1110", "T1550.002"],
        "tactic":    "Credential Access",
        "severity":  "Medium",
        "title":     "NTLM Authentication Attempt",
        "risk_note": "NTLM auth outside expected patterns may indicate credential replay.",
    },

    # ── Execution ──────────────────────────────────────────
    4688: {
        "ttp_ids":   ["T1059", "T1059.001", "T1059.003"],
        "tactic":    "Execution",
        "severity":  "Medium",
        "title":     "Process Created",
        "risk_note": "Monitor for LOLBins: powershell, cmd, wscript, mshta, regsvr32.",
    },
    4103: {
        "ttp_ids":   ["T1059.001"],
        "tactic":    "Execution",
        "severity":  "High",
        "title":     "PowerShell Module Logging",
        "risk_note": "Encoded commands or suspicious module loads detected.",
    },
    4104: {
        "ttp_ids":   ["T1059.001", "T1027"],
        "tactic":    "Execution / Defense Evasion",
        "severity":  "High",
        "title":     "PowerShell Script Block Logging",
        "risk_note": "Script block with obfuscation or download cradles is high-risk.",
    },

    # ── Persistence ────────────────────────────────────────
    4698: {
        "ttp_ids":   ["T1053.005"],
        "tactic":    "Persistence",
        "severity":  "High",
        "title":     "Scheduled Task Created",
        "risk_note": "Unexpected scheduled tasks are a common persistence mechanism.",
    },
    4702: {
        "ttp_ids":   ["T1053.005"],
        "tactic":    "Persistence",
        "severity":  "Medium",
        "title":     "Scheduled Task Updated",
        "risk_note": "Modification of existing tasks may indicate hijacking.",
    },
    7045: {
        "ttp_ids":   ["T1543.003"],
        "tactic":    "Persistence",
        "severity":  "High",
        "title":     "New Service Installed",
        "risk_note": "Newly installed services should be verified against baseline.",
    },

    # ── Lateral Movement ───────────────────────────────────
    4624: {
        "ttp_ids":   ["T1021.001", "T1021.002", "T1078"],
        "tactic":    "Lateral Movement",
        "severity":  "Low",
        "title":     "Successful Logon",
        "risk_note": "Logon Type 3 (network) or Type 10 (remote interactive) warrants review.",
    },
    4672: {
        "ttp_ids":   ["T1078.002", "T1134"],
        "tactic":    "Privilege Escalation",
        "severity":  "Medium",
        "title":     "Special Privileges Assigned",
        "risk_note": "Admin-equivalent privileges assigned at logon.",
    },

    # ── Defense Evasion ────────────────────────────────────
    1102: {
        "ttp_ids":   ["T1070.001"],
        "tactic":    "Defense Evasion",
        "severity":  "High",
        "title":     "Audit Log Cleared",
        "risk_note": "Security log cleared — high-confidence indicator of attacker covering tracks.",
    },
    4719: {
        "ttp_ids":   ["T1562.002"],
        "tactic":    "Defense Evasion",
        "severity":  "High",
        "title":     "System Audit Policy Changed",
        "risk_note": "Audit policy change may be attempt to disable logging.",
    },

    # ── Discovery ──────────────────────────────────────────
    4798: {
        "ttp_ids":   ["T1087.001"],
        "tactic":    "Discovery",
        "severity":  "Low",
        "title":     "User's Local Group Membership Enumerated",
        "risk_note": "Recon activity — enumeration of local group memberships.",
    },
    4799: {
        "ttp_ids":   ["T1069.001"],
        "tactic":    "Discovery",
        "severity":  "Low",
        "title":     "Security-Enabled Local Group Membership Enumerated",
        "risk_note": "Group enumeration — common in initial recon phase.",
    },
}

SEVERITY_ORDER = {"High": 3, "Medium": 2, "Low": 1}

# ─────────────────────────────────────────────────────────────
# Data Classes
# ─────────────────────────────────────────────────────────────

@dataclass
class LogEvent:
    """單條原始 Windows Event Log。"""
    event_id:    int
    timestamp:   datetime
    computer:    str
    account:     str
    source_ip:   Optional[str]   = None
    description: str             = ""
    raw:         Dict[str, Any]  = field(default_factory=dict)


@dataclass
class TriagedLog:
    """Triage 後的結構化結果，供 pipeline / report 使用。"""
    event:       LogEvent
    ttp_ids:     List[str]
    tactic:      str
    severity:    str              # High / Medium / Low
    title:       str
    risk_note:   str
    enriched_ttps: List[Dict]    = field(default_factory=list)
    # 方便 OpenClaw 等 multi-agent 框架 JSON 序列化
    def to_dict(self) -> Dict[str, Any]:
        return {
            "event_id":    self.event.event_id,
            "timestamp":   self.event.timestamp.isoformat(),
            "computer":    self.event.computer,
            "account":     self.event.account,
            "source_ip":   self.event.source_ip,
            "description": self.event.description,
            "ttp_ids":     self.ttp_ids,
            "tactic":      self.tactic,
            "severity":    self.severity,
            "title":       self.title,
            "risk_note":   self.risk_note,
            "enriched_ttps": self.enriched_ttps,
        }


# ─────────────────────────────────────────────────────────────
# Log Processor
# ─────────────────────────────────────────────────────────────

class LogProcessor:
    """
    將 LogEvent 列表映射到 MITRE TTP，並透過 RAGEngine 補充技術說明。

    設計為無狀態（stateless）以便在 multi-agent 框架中並行執行。
    """

    def __init__(self, rag=None):
        """
        Args:
            rag: RAGEngine 實例（可選）。提供時會補充 MITRE 說明；
                 不提供時仍能執行 triage，enriched_ttps 為空。
        """
        self.rag = rag

    def process(self, events: List[LogEvent]) -> List[TriagedLog]:
        """
        主處理入口。

        Args:
            events: 原始 LogEvent 列表

        Returns:
            TriagedLog 列表，按 severity 降序排列
        """
        results: List[TriagedLog] = []

        for event in events:
            mapping = EVENT_TTP_MAP.get(event.event_id)
            if not mapping:
                # 未知 Event ID — 仍建立低優先紀錄
                results.append(TriagedLog(
                    event=event,
                    ttp_ids=[],
                    tactic="Unknown",
                    severity="Low",
                    title=f"Event ID {event.event_id}",
                    risk_note="No TTP mapping found. Manual review recommended.",
                ))
                continue

            enriched = []
            if self.rag:
                enriched = self.rag.enrich_ttps(mapping["ttp_ids"])

            results.append(TriagedLog(
                event=event,
                ttp_ids=mapping["ttp_ids"],
                tactic=mapping["tactic"],
                severity=mapping["severity"],
                title=mapping["title"],
                risk_note=mapping["risk_note"],
                enriched_ttps=enriched,
            ))

        # Sort: High → Medium → Low, then by timestamp desc
        results.sort(
            key=lambda x: (
                -SEVERITY_ORDER.get(x.severity, 0),
                -x.event.timestamp.timestamp(),
            )
        )
        return results


# ─────────────────────────────────────────────────────────────
# Simulator — 模擬真實 Windows Event Log 輸入
# ─────────────────────────────────────────────────────────────

_SAMPLE_ACCOUNTS = ["jsmith", "admin", "svc_backup", "SYSTEM", "Guest", "helpdesk01"]
_SAMPLE_COMPUTERS = ["WIN-DC01", "WORKSTATION-42", "SRV-FILE01", "LAPTOP-CEO"]
_SAMPLE_IPS = ["192.168.1.55", "10.0.0.23", "172.16.8.9", "203.0.113.45"]

_SCENARIO_PRESETS: Dict[str, List[int]] = {
    "brute_force": [4625, 4625, 4625, 4625, 4625, 4624, 4672],
    "lateral_movement": [4624, 4648, 4624, 4672, 4688],
    "persistence": [4698, 7045, 4688],
    "defense_evasion": [1102, 4719, 4688, 4103],
    "kerberoasting": [4768, 4769, 4769, 4769, 4776],
    "full_attack": [4625, 4625, 4624, 4648, 4688, 4104, 4698, 4672, 1102],
}


def simulate_logs(
    scenario: str = "brute_force",
    count: Optional[int] = None,
    custom_event_ids: Optional[List[int]] = None,
) -> List[LogEvent]:
    """
    產生模擬 Windows Event Logs。

    Args:
        scenario:         預設情境名稱（見 _SCENARIO_PRESETS）
        count:            覆蓋預設數量
        custom_event_ids: 完全自訂 Event ID 序列

    Returns:
        List[LogEvent]，時間戳為最近 60 分鐘內的隨機時間
    """
    if custom_event_ids:
        event_ids = custom_event_ids
    else:
        event_ids = _SCENARIO_PRESETS.get(scenario, _SCENARIO_PRESETS["brute_force"])

    if count:
        event_ids = (event_ids * (count // len(event_ids) + 1))[:count]

    now = datetime.utcnow()
    events: List[LogEvent] = []

    for i, eid in enumerate(event_ids):
        mapping = EVENT_TTP_MAP.get(eid, {})
        ts = now - timedelta(minutes=random.randint(0, 59), seconds=random.randint(0, 59))
        account = random.choice(_SAMPLE_ACCOUNTS)
        computer = random.choice(_SAMPLE_COMPUTERS)
        src_ip = random.choice(_SAMPLE_IPS) if eid in (4625, 4624, 4648, 4776) else None

        events.append(LogEvent(
            event_id=eid,
            timestamp=ts,
            computer=computer,
            account=account,
            source_ip=src_ip,
            description=mapping.get("title", f"Event {eid}"),
            raw={
                "EventID": eid,
                "TimeCreated": ts.isoformat(),
                "Computer": computer,
                "SubjectUserName": account,
                "IpAddress": src_ip,
                "LogonType": 3 if eid in (4624, 4648) else None,
            },
        ))

    # Sort chronologically
    events.sort(key=lambda e: e.timestamp)
    return events


# ─────────────────────────────────────────────────────────────
# Public entry point  (stable interface for pipeline / OpenClaw)
# ─────────────────────────────────────────────────────────────

def triage_logs(
    events: List[LogEvent],
    rag=None,
) -> List[TriagedLog]:
    """
    Public entry point — stable interface for pipeline and external frameworks.

    Args:
        events: List[LogEvent] from any source (simulator, EVTX parser, API)
        rag:    RAGEngine instance for MITRE enrichment (optional)

    Returns:
        List[TriagedLog] sorted by severity desc
    """
    processor = LogProcessor(rag=rag)
    return processor.process(events)
