"""
rag_engine.py — ThreatHunt-GPT RAG Core
Handles FAISS vector search over MITRE ATT&CK techniques + CTI metadata.
"""

import json
import os
import sys
import numpy as np
import faiss
from sentence_transformers import SentenceTransformer
from typing import List, Dict, Any, Optional, Tuple

EMBED_MODEL = "all-MiniLM-L6-v2"

# Resolve the data files against this file, not the working directory.
# An MCP client launches the server from an arbitrary CWD, where a relative
# path either crashes (the FAISS index) or silently loads nothing (aliases).
_HERE = os.path.dirname(os.path.abspath(__file__))



# ── ICS ATT&CK technique fallback (T0xxx not in enterprise JSON) ──────
ICS_TECHNIQUES: Dict[str, Dict] = {
    "T0800": {"name": "Activate Firmware Update Mode", "description": "Adversaries may activate firmware update mode to enable access to the firmware of a target device.", "domain": "ics-attack"},
    "T0801": {"name": "Monitor Process State", "description": "Adversaries may gather information about the current state of a process.", "domain": "ics-attack"},
    "T0802": {"name": "Automated Collection", "description": "Adversaries may use automated techniques for collecting internal data from a compromised ICS environment.", "domain": "ics-attack"},
    "T0803": {"name": "Block Command Message", "description": "Adversaries may block a command message from reaching its intended target to prevent control actions from taking effect.", "domain": "ics-attack"},
    "T0804": {"name": "Block Reporting Message", "description": "Adversaries may block or prevent reporting messages from reaching their intended target.", "domain": "ics-attack"},
    "T0805": {"name": "Block Serial COM", "description": "Adversaries may block access to serial COM to prevent operators from issuing commands.", "domain": "ics-attack"},
    "T0807": {"name": "Command-Line Interface", "description": "Adversaries may use command-line interfaces to interact with systems and execute commands.", "domain": "ics-attack"},
    "T0812": {"name": "Default Credentials", "description": "Adversaries may use default credentials to gain initial access to network infrastructure.", "domain": "ics-attack"},
    "T0813": {"name": "Denial of Control", "description": "Adversaries may cause a denial of control to temporarily prevent operators from controlling equipment.", "domain": "ics-attack"},
    "T0814": {"name": "Denial of Service", "description": "Adversaries may perform Denial-of-Service attacks to degrade or block the availability of services.", "domain": "ics-attack"},
    "T0815": {"name": "Denial of View", "description": "Adversaries may cause a denial of view to prevent operators from observing the state of equipment.", "domain": "ics-attack"},
    "T0816": {"name": "Device Restart/Shutdown", "description": "Adversaries may forcibly restart or shutdown a device in an ICS environment.", "domain": "ics-attack"},
    "T0817": {"name": "Drive-by Compromise", "description": "Adversaries may gain access to a system through a user visiting a website over the normal course of browsing.", "domain": "ics-attack"},
    "T0818": {"name": "Engineering Workstation Compromise", "description": "Adversaries may compromise an engineering workstation to gain a foothold in an ICS environment.", "domain": "ics-attack"},
    "T0819": {"name": "Exploit Public-Facing Application", "description": "Adversaries may attempt to take advantage of a weakness in an Internet-facing computer or program.", "domain": "ics-attack"},
    "T0820": {"name": "Exploitation for Evasion", "description": "Adversaries may exploit a software vulnerability to evade detection in an ICS environment.", "domain": "ics-attack"},
    "T0821": {"name": "Modify Controller Tasking", "description": "Adversaries may modify the tasking of a controller to allow for the execution of their own programs.", "domain": "ics-attack"},
    "T0822": {"name": "External Remote Services", "description": "Adversaries may leverage external-facing remote services to initially access and persist within an ICS network.", "domain": "ics-attack"},
    "T0825": {"name": "Location Identification", "description": "Adversaries may perform location identification to learn where they are geographically after compromising a system.", "domain": "ics-attack"},
    "T0826": {"name": "Loss of Availability", "description": "Adversaries may attempt to disrupt essential components or systems to prevent owner and operator from delivering products.", "domain": "ics-attack"},
    "T0827": {"name": "Loss of Control", "description": "Adversaries may seek to achieve a sustained loss of control over the ICS environment.", "domain": "ics-attack"},
    "T0828": {"name": "Loss of Productivity and Revenue", "description": "Adversaries may cause loss of productivity and revenue through disruption and theft of a production environment.", "domain": "ics-attack"},
    "T0829": {"name": "Loss of Protection", "description": "Adversaries may seek to disable the protection functions of safety instrumented systems (SIS).", "domain": "ics-attack"},
    "T0830": {"name": "Adversary-in-the-Middle", "description": "Adversaries with privileged network access may seek to modify network traffic in real time using adversary-in-the-middle techniques.", "domain": "ics-attack"},
    "T0831": {"name": "Manipulation of Control", "description": "Adversaries may manipulate physical process control within the target environment.", "domain": "ics-attack"},
    "T0832": {"name": "Manipulation of View", "description": "Adversaries may attempt to manipulate the information reported back to operators or historian.", "domain": "ics-attack"},
    "T0833": {"name": "Modify Alarm Settings", "description": "Adversaries may modify alarm settings to prevent alerts that may inform operators of their attack.", "domain": "ics-attack"},
    "T0835": {"name": "Manipulate I/O Image", "description": "Adversaries may manipulate the I/O image of PLCs through various means to prevent them from responding correctly.", "domain": "ics-attack"},
    "T0836": {"name": "Modify Parameter", "description": "Adversaries may modify parameters used to instruct industrial control system devices.", "domain": "ics-attack"},
    "T0837": {"name": "Loss of Safety", "description": "Adversaries may compromise safety instrumented systems (SIS) devices to disable preventative actions.", "domain": "ics-attack"},
    "T0839": {"name": "Module Firmware", "description": "Adversaries may install malicious or vulnerable firmware onto modular hardware devices.", "domain": "ics-attack"},
    "T0840": {"name": "Network Connection Enumeration", "description": "Adversaries may perform network connection enumeration to discover information about device communications.", "domain": "ics-attack"},
    "T0841": {"name": "Network Sniffing", "description": "Adversaries may use network sniffing to capture and extract network traffic in an ICS environment.", "domain": "ics-attack"},
    "T0842": {"name": "Network-Wide Scanning", "description": "Adversaries may perform network-wide scanning to identify hosts and services running in the ICS environment.", "domain": "ics-attack"},
    "T0843": {"name": "Program Download", "description": "Adversaries may perform a program download to transfer a user program to a controller.", "domain": "ics-attack"},
    "T0845": {"name": "Program Upload", "description": "Adversaries may perform a program upload to transfer a copy of a program from a controller.", "domain": "ics-attack"},
    "T0846": {"name": "Remote System Discovery", "description": "Adversaries may attempt to get a listing of other systems by IP address, hostname, or other logical identifier.", "domain": "ics-attack"},
    "T0847": {"name": "Replication Through Removable Media", "description": "Adversaries may move onto systems by copying malware to removable media and exploiting autorun features.", "domain": "ics-attack"},
    "T0848": {"name": "Rogue Master", "description": "Adversaries may setup a rogue master to leverage control server functions to communicate with slave devices.", "domain": "ics-attack"},
    "T0849": {"name": "Masquerading", "description": "Adversaries may attempt to manipulate features of their artifacts to make them appear legitimate or benign to users.", "domain": "ics-attack"},
    "T0851": {"name": "Rootkit", "description": "Adversaries may use rootkits to hide the presence of programs, files, network connections, services, drivers, and other system components.", "domain": "ics-attack"},
    "T0852": {"name": "Screen Capture", "description": "Adversaries may attempt to take screen captures of the desktop to gather information over the course of an operation.", "domain": "ics-attack"},
    "T0853": {"name": "Scripting", "description": "Adversaries may use scripts to aid in operations and perform multiple actions that would otherwise be manual.", "domain": "ics-attack"},
    "T0855": {"name": "Unauthorized Command Message", "description": "Adversaries may send unauthorized commands to a device to change the physical state of the device.", "domain": "ics-attack"},
    "T0856": {"name": "Spoof Reporting Message", "description": "Adversaries may spoof reporting messages in order to present false information to operators or control applications.", "domain": "ics-attack"},
    "T0857": {"name": "System Firmware", "description": "Adversaries may exploit the firmware update feature of devices to install malicious firmware.", "domain": "ics-attack"},
    "T0858": {"name": "Change Credential", "description": "Adversaries may change credentials to prevent legitimate users from accessing the system or to hide adversary activity.", "domain": "ics-attack"},
    "T0859": {"name": "Valid Accounts", "description": "Adversaries may steal the credentials of a specific user or service account using credential access techniques or capture credentials.", "domain": "ics-attack"},
    "T0860": {"name": "Wireless Compromise", "description": "Adversaries may compromise wireless communications to gain access or persist in an ICS environment.", "domain": "ics-attack"},
    "T0861": {"name": "Point & Tag Identification", "description": "Adversaries may identify or enumerate tags and points in an OT environment to understand I/O values.", "domain": "ics-attack"},
    "T0862": {"name": "Supply Chain Compromise", "description": "Adversaries may manipulate products or product delivery mechanisms prior to receipt by a final consumer.", "domain": "ics-attack"},
    "T0863": {"name": "User Execution", "description": "Adversaries may rely on a specific user or automated process to execute a malicious payload.", "domain": "ics-attack"},
    "T0864": {"name": "Transient Cyber Asset", "description": "Adversaries may target removable devices to gain initial access to systems in ICS environments.", "domain": "ics-attack"},
    "T0865": {"name": "Spearphishing Attachment", "description": "Adversaries may send spearphishing emails with a malicious attachment to compromise ICS systems.", "domain": "ics-attack"},
    "T0866": {"name": "Exploitation of Remote Services", "description": "Adversaries may exploit remote services to initially access or pivot within an ICS environment.", "domain": "ics-attack"},
    "T0867": {"name": "Lateral Tool Transfer", "description": "Adversaries may transfer tools or other files between systems in a compromised ICS environment.", "domain": "ics-attack"},
    "T0869": {"name": "Standard Application Layer Protocol", "description": "Adversaries may communicate using application layer protocols to avoid detection or network filtering.", "domain": "ics-attack"},
    "T0871": {"name": "Execution through API", "description": "Adversaries may abuse functions of legitimate software to run their command and control.", "domain": "ics-attack"},
    "T0872": {"name": "Indicator Removal on Host", "description": "Adversaries may delete or alter generated artifacts on a host system to evade detection.", "domain": "ics-attack"},
    "T0873": {"name": "Project File Infection", "description": "Adversaries may attempt to infect project files with malicious code to gain execution on target systems.", "domain": "ics-attack"},
    "T0874": {"name": "Hooking", "description": "Adversaries may use hooking to load and execute malicious code within the context of another process.", "domain": "ics-attack"},
    "T0878": {"name": "Alarm Suppression", "description": "Adversaries may target protection function alarms to prevent them from notifying operators of their actions.", "domain": "ics-attack"},
    "T0879": {"name": "Damage to Property", "description": "Adversaries may cause damage and destruction of property to infrastructure, equipment, and resources.", "domain": "ics-attack"},
    "T0880": {"name": "Loss of View", "description": "Adversaries may cause a loss of view in the control system environment to prevent operators from observing the state.", "domain": "ics-attack"},
    "T0881": {"name": "Service Stop", "description": "Adversaries may stop or disable services on a system to render those services unavailable to legitimate users.", "domain": "ics-attack"},
    "T0882": {"name": "Theft of Operational Information", "description": "Adversaries may steal operational information on a production environment to inform their attack planning.", "domain": "ics-attack"},
    "T0883": {"name": "Internet Accessible Device", "description": "Adversaries may gain access to the network through devices directly connected to the internet.", "domain": "ics-attack"},
    "T0884": {"name": "Connection Proxy", "description": "Adversaries may use a connection proxy to direct network traffic between systems or act as an intermediary.", "domain": "ics-attack"},
    "T0886": {"name": "Remote Services", "description": "Adversaries may use remote services such as SSH or RDP to move laterally through the ICS network.", "domain": "ics-attack"},
    "T0887": {"name": "Wireless Sniffing", "description": "Adversaries may seek to capture radio frequency communications.", "domain": "ics-attack"},
    "T0888": {"name": "Remote System Information Discovery", "description": "Adversaries may attempt to get a listing of other systems by IP address or hostname in the ICS environment.", "domain": "ics-attack"},
    "T0889": {"name": "Modify Program", "description": "Adversaries may modify or add program code to a controller to change how it interacts with physical processes.", "domain": "ics-attack"},
    "T0891": {"name": "Hardcoded Credentials", "description": "Adversaries may use hardcoded credentials present in the software or firmware to gain access.", "domain": "ics-attack"},
}

class RAGEngine:
    def __init__(
        self,
        faiss_path:    Optional[str] = None,
        metadata_path: Optional[str] = None,
        mitre_path:    Optional[str] = None,
        aliases_path:  Optional[str] = None,
    ):
        faiss_path    = faiss_path    or os.path.join(_HERE, "combined_index.faiss")
        metadata_path = metadata_path or os.path.join(_HERE, "combined_metadata.json")
        mitre_path    = mitre_path    or os.path.join(_HERE, "combined_mitre.json")
        aliases_path  = aliases_path  or os.path.join(_HERE, "group_aliases.json")

        self.model = SentenceTransformer(EMBED_MODEL)

        # Load FAISS index + CTI metadata
        self.index = faiss.read_index(faiss_path)
        with open(metadata_path, "r") as f:
            self.metadata: List[Dict] = json.load(f)

        # Load MITRE technique/malware/tool lookup
        with open(mitre_path, "r") as f:
            raw = json.load(f)
        self.mitre_lookup: Dict[str, Dict] = {
            e["id"]: e for e in raw["entries"] if "id" in e
        }

        # Build fast group lookups from CTI metadata
        self._cti_by_group: Dict[str, Dict] = {}
        for entry in self.metadata:
            title = entry.get("title", "").strip()
            if title not in self._cti_by_group:
                self._cti_by_group[title] = {}
            src = entry.get("source_type", "")
            self._cti_by_group[title][src] = entry.get("text", "")

        # Optional alias table (built by build_aliases.py from MITRE STIX).
        # Keep only aliases whose canonical group exists in our CTI data.
        self._alias_to_group: Dict[str, str] = {}
        if os.path.exists(aliases_path):
            with open(aliases_path, "r") as f:
                raw_aliases: Dict[str, str] = json.load(f)
            self._alias_to_group = {
                a: g for a, g in raw_aliases.items() if g in self._cti_by_group
            }
            print(f"Loaded {len(self._alias_to_group)} group aliases", file=sys.stderr)

        added = self.enrich_index_with_mitre()
        print(f"Enriched index with {added} MITRE technique entries", file=sys.stderr)

    # ------------------------------------------------------------------
    # Group lookups
    # ------------------------------------------------------------------
    def get_group_names(self) -> List[str]:
        return sorted(self._cti_by_group.keys())

    def find_group(self, query: str) -> Optional[str]:
        """Return the canonical group name for `query`, or None.

        Thin wrapper over resolve_group() for callers that do not need to
        know which pass matched (e.g. the MCP server, the compare view).
        """
        return self.resolve_group(query)[0]

    def resolve_group(self, query: str) -> Tuple[Optional[str], Optional[str]]:
        """
        Resolve `query` to (canonical group name, match method).
        match method is one of: "exact", "alias", "word_boundary",
        "substring", "semantic" — or (None, None) when nothing matches.

        精確比對優先，避免 APT1 匹配到 APT12 的 bug。
        比對順序：
          1. 完整字串相等（大小寫不分）
          1.5 MITRE 別名表（group_aliases.json，若存在）
          2. query 完整出現在 name 中，且前後是字詞邊界（word boundary）
          3. name 完整出現在 query 中，且前後是字詞邊界
          4. 向量語意搜尋 fallback
        """
        import re
        q = query.strip()
        q_upper = q.upper()

        # Pass 1: 完整相等
        for name in self._cti_by_group:
            if name.upper() == q_upper:
                return name, "exact"

        # Pass 1.5: 別名比對（例："Fancy Bear" -> "APT28"）
        # Embeddings can't resolve codenames, so aliases are a structured lookup.
        alias_hit = self._alias_to_group.get(q_upper)
        if alias_hit:
            return alias_hit, "alias"

        # Pass 2: word-boundary 比對
        # 例："APT1" 不會匹配 "APT12" 因為 APT1 後面跟著數字
        for name in self._cti_by_group:
            pattern = r'(?<![A-Z0-9])' + re.escape(name.upper()) + r'(?![A-Z0-9])'
            if re.search(pattern, q_upper):
                return name, "word_boundary"

        # Pass 3: query name（For example: "lazarus" match "Lazarus Group"）
        for name in self._cti_by_group:
            pattern = r'(?<![A-Z0-9])' + re.escape(q_upper) + r'(?![A-Z0-9])'
            if re.search(pattern, name.upper()):
                return name, "substring"

        # Pass 4: semantic fallback, guarded by distance AND margin.
        #
        # Two independent guards, because each catches what the other misses:
        #
        #   distance — is the best candidate plausibly related at all?
        #       Rejects junk ("qwertyuiop" scores 1.72, past anything real)
        #       even when nothing competes with it.
        #
        #   margin — is the best candidate clearly better than the runner-up?
        #       Rejects coin-flips. "Iranian group that used the Shamoon wiper"
        #       puts Andariel at 1.332 and the correct APT33 at 1.336; a 0.004
        #       gap means the embedding cannot tell them apart, so answering
        #       at all is guessing.
        #
        # Measured on eval/dataset.jsonl: distance alone (at any bound loose
        # enough to accept real matches) returns wrong groups; margin alone
        # accepts junk that happens to have no runner-up. Together: 0 wrong.
        #
        # top_k is deliberately wide. enrich_index_with_mitre() adds ~900
        # technique vectors to an index holding only 24 group bios, so a
        # descriptive query can fill its first hits with techniques and leave
        # no group to compare against at all.
        candidates = [
            r for r in self.semantic_search(q, top_k=self.GROUP_SEARCH_TOP_K)
            if r.get("source_type") == "cti_summary"
            and r.get("title", "") in self._cti_by_group
        ]
        if not candidates:
            return None, None

        best = candidates[0]
        runner_up = candidates[1]["score"] if len(candidates) > 1 else None

        if not self._close_enough(best["score"]):
            return None, None
        if not self._clear_winner(best["score"], runner_up):
            return None, None

        return best.get("title", ""), "semantic"

    # How many raw hits to pull before filtering down to group summaries.
    # The index is ~97% MITRE technique vectors, so a narrow top_k often
    # returns no group at all.
    GROUP_SEARCH_TOP_K = 20

    # Tuned on eval/dataset.jsonl (sweep: eval/diagnose_margin.py).
    # METRIC_L2: smaller = closer.  METRIC_INNER_PRODUCT: larger = closer.
    #
    # The L2 bounds are measured. The previous MAX_L2 of 1.0 sat below the
    # entire observed score distribution — the best correct match scores
    # 1.026 — so this fallback had never once fired.
    #
    # 1.45 clears the real matches (1.03–1.41) and excludes junk (1.72+) and
    # near-misses like "Wizard Spider" (1.534). 1.60 also scores 0 wrong but
    # leaves that one to the margin guard alone, so the tighter bound stays.
    GROUP_MATCH_MAX_L2 = 1.45
    GROUP_MATCH_MIN_MARGIN_L2 = 0.20

    # NOT measured: the index in use is L2, so these inner-product values are
    # still the original guesses. Re-run the sweep before trusting an IP index.
    GROUP_MATCH_MIN_IP = 0.5
    GROUP_MATCH_MIN_MARGIN_IP = 0.05

    def _is_inner_product(self) -> bool:
        return self.index.metric_type == faiss.METRIC_INNER_PRODUCT

    def _close_enough(self, score: float) -> bool:
        """Is the best candidate plausibly related to the query at all?"""
        if self._is_inner_product():
            return score >= self.GROUP_MATCH_MIN_IP
        return score <= self.GROUP_MATCH_MAX_L2

    def _clear_winner(self, best: float, runner_up: Optional[float]) -> bool:
        """Is the best candidate distinguishable from the next one?

        No runner-up inside top_k means nothing competes, which counts as
        clear — _close_enough() is what rejects those cases when the single
        candidate is simply far away.
        """
        if runner_up is None:
            return True
        if self._is_inner_product():
            return (best - runner_up) >= self.GROUP_MATCH_MIN_MARGIN_IP
        return (runner_up - best) >= self.GROUP_MATCH_MIN_MARGIN_L2

    def get_cti_summary(self, group_name: str) -> str:
        data = self._cti_by_group.get(group_name, {})
        return data.get("cti_summary", "No CTI summary available.")

    def get_ttp_ids(self, group_name: str) -> List[str]:
        data = self._cti_by_group.get(group_name, {})
        raw = data.get("cti_techniques", "")
        return [t.strip() for t in raw.split() if t.strip()]

    # ------------------------------------------------------------------
    # MITRE enrichment
    # ------------------------------------------------------------------
    def enrich_ttps(self, ttp_ids: List[str]) -> List[Dict]:
        enriched = []
        for tid in ttp_ids:
            entry = self.mitre_lookup.get(tid)
            if entry:
                enriched.append({
                    "id": tid,
                    "name": entry.get("name", "Unknown"),
                    "description": entry.get("description", "")[:500],
                    "domain": entry.get("domain", "enterprise-attack"),
                })
            else:
                # Fallback: check ICS ATT&CK lookup
                ics_entry = ICS_TECHNIQUES.get(tid)
                if ics_entry:
                    enriched.append({
                        "id": tid,
                        "name": ics_entry["name"],
                        "description": ics_entry["description"],
                        "domain": ics_entry["domain"],
                    })
                else:
                    enriched.append({
                        "id": tid,
                        "name": f"Technique {tid}",
                        "description": f"See https://attack.mitre.org/techniques/{tid.replace('.','/')}/ for details.",
                        "domain": "unknown",
                    })
        return enriched

    # ------------------------------------------------------------------
    # Index enrichment (prototype)
    # ------------------------------------------------------------------
    def enrich_index_with_mitre(self) -> int:
        """Append MITRE technique descriptions to the in-memory FAISS index.

        The original on-disk corpus only has short group bios, so TTP-style
        queries ("dump credentials from LSASS") have nothing to match. This
        indexes each technique's `"{name}. {description}"` so those queries
        land on the right technique entry (e.g. T1003.001).
        """
        import re
        tid_re = re.compile(r"^T\d{4}(?:\.\d{3})?$")

        new_texts: List[str] = []
        new_meta: List[Dict] = []
        seen = set(
            d.get("title") for d in self.metadata
            if d.get("source_type") == "mitre_technique"
        )

        def _add(tid: str, name: str, desc: str, domain: str) -> None:
            if tid in seen or not desc:
                return
            seen.add(tid)
            text = f"{name}. {desc}"
            new_texts.append(text)
            new_meta.append({
                "title": tid,
                "source_type": "mitre_technique",
                "name": name,
                "domain": domain,
                "text": text,
            })

        for tid, entry in self.mitre_lookup.items():
            if not tid_re.match(tid):
                continue
            _add(
                tid,
                entry.get("name", tid),
                entry.get("description", ""),
                entry.get("domain", "enterprise-attack"),
            )
        for tid, entry in ICS_TECHNIQUES.items():
            _add(tid, entry["name"], entry["description"], entry["domain"])

        if not new_texts:
            return 0

        vecs = np.array(self.model.encode(new_texts), dtype="float32")
        self.index.add(vecs)
        self.metadata.extend(new_meta)
        return len(new_meta)

    # ------------------------------------------------------------------
    # Semantic vector search
    # ------------------------------------------------------------------
    def semantic_search(self, query: str, top_k: int = 5) -> List[Dict]:
        vec = self.model.encode([query])
        distances, indices = self.index.search(np.array(vec, dtype="float32"), top_k)
        results = []
        for dist, idx in zip(distances[0], indices[0]):
            if idx < len(self.metadata):
                entry = self.metadata[idx].copy()
                entry["score"] = float(dist)
                results.append(entry)
        return results

    # ------------------------------------------------------------------
    # Full pipeline
    # ------------------------------------------------------------------
    def full_lookup(self, group_name: str) -> Dict[str, Any]:
        summary = self.get_cti_summary(group_name)
        ttp_ids = self.get_ttp_ids(group_name)
        enriched = self.enrich_ttps(ttp_ids)
        return {
            "group": group_name,
            "summary": summary,
            "ttp_count": len(ttp_ids),
            "ttps": enriched,
        }
