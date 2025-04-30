import json
import os

def load_entries_from_folder(folder_path, entry_type):
    entries = []
    for filename in os.listdir(folder_path):
        if filename.endswith(".json"):
            with open(os.path.join(folder_path, filename), 'r') as f:
                data = json.load(f)
                if data.get("type") == "bundle" and "objects" in data:
                    objects = data["objects"]
                else:
                    objects = [data]

                for obj in objects:
                    if entry_type == "technique" and obj.get("type") == "attack-pattern":
                        ext_refs = obj.get('external_references', [])
                        attack_id = None
                        for ref in ext_refs:
                            if ref.get('source_name') == 'mitre-attack':
                                attack_id = ref.get('external_id')
                                break
                        if attack_id and 'description' in obj and 'name' in obj:
                            entries.append({
                                "type": "technique",
                                "id": attack_id,
                                "name": obj['name'],
                                "description": obj['description'],
                                "domain": "enterprise-attack"
                            })

                    if entry_type in ["group", "malware", "tool"] and obj.get("type") == entry_type:
                        ext_refs = obj.get('external_references', [])
                        attack_id = None
                        for ref in ext_refs:
                            if ref.get('source_name') == 'mitre-attack':
                                attack_id = ref.get('external_id')
                                break
                        if attack_id and 'description' in obj and 'name' in obj:
                            entry = {
                                "type": entry_type,
                                "id": attack_id,
                                "name": obj['name'],
                                "description": obj['description'],
                                "domain": "enterprise-attack"
                            }
                            if entry_type == "group":
                                entry["aliases"] = obj.get("aliases", [])
                            entries.append(entry)
    return entries

def merge_mitre_data(attack_pattern_folder, group_folder, malware_folder, tool_folder, output_file):
    all_entries = []
    all_entries += load_entries_from_folder(attack_pattern_folder, "technique")
    all_entries += load_entries_from_folder(group_folder, "group")
    all_entries += load_entries_from_folder(malware_folder, "malware")
    all_entries += load_entries_from_folder(tool_folder, "tool")

    with open(output_file, 'w') as out_f:
        json.dump({"entries": all_entries}, out_f, indent=2)

    print(f"Combined MITRE data with {len(all_entries)} entries into {output_file}")

if __name__ == "__main__":
    merge_mitre_data(
        "cti/enterprise-attack/attack-pattern",
        "cti/enterprise-attack/intrusion-set",
        "cti/enterprise-attack/malware",
        "cti/enterprise-attack/tool",
        "data/combined_mitre.json"
    )
