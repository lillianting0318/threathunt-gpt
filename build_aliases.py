"""
One-time script: build group_aliases.json from MITRE ATT&CK (enterprise) STIX data.

Usage (from the repo root):
    python build_aliases.py

Output: group_aliases.json  ->  {"FANCY BEAR": "APT28", "SOFACY": "APT28", ...}
Keys are upper-cased aliases; values are canonical MITRE group names.
Aliases shared by more than one group are dropped as ambiguous.
"""

import json
import sys
import urllib.request
from collections import defaultdict

STIX_URL = (
    "https://raw.githubusercontent.com/mitre-attack/attack-stix-data/"
    "master/enterprise-attack/enterprise-attack.json"
)
OUT_PATH = "group_aliases.json"


def main() -> None:
    print("Downloading MITRE ATT&CK STIX (~50 MB)...", file=sys.stderr)
    with urllib.request.urlopen(STIX_URL) as resp:
        bundle = json.load(resp)

    alias_to_groups = defaultdict(set)
    n_groups = 0
    for obj in bundle["objects"]:
        if obj.get("type") != "intrusion-set":
            continue
        if obj.get("revoked") or obj.get("x_mitre_deprecated"):
            continue
        n_groups += 1
        canonical = obj["name"]
        for alias in obj.get("aliases", []) + [canonical]:
            alias_to_groups[alias.strip().upper()].add(canonical)

    aliases, ambiguous = {}, []
    for alias, groups in alias_to_groups.items():
        if len(groups) == 1:
            aliases[alias] = next(iter(groups))
        else:
            ambiguous.append((alias, sorted(groups)))

    with open(OUT_PATH, "w") as f:
        json.dump(dict(sorted(aliases.items())), f, indent=2, ensure_ascii=False)

    print(f"{n_groups} groups, {len(aliases)} aliases -> {OUT_PATH}", file=sys.stderr)
    for alias, groups in ambiguous:
        print(f"  skipped ambiguous alias {alias!r}: {groups}", file=sys.stderr)


if __name__ == "__main__":
    main()
