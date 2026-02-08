import xml.etree.ElementTree as ET
import json

def strip_ns(tag):
    return tag.split("}")[-1] if "}" in tag else tag

def detect_stix_version(raw):
    try:
        text = raw.decode("utf-8")
    except Exception:
        try:
            text = str(raw)
        except Exception:
            return "unknown"
    if "<STIX_Package" in text or text.strip().startswith("<?xml"):
        return "1.x"
    if '"spec_version"' in text:
        if '"2.1"' in text:
            return "2.1"
        if '"2.0"' in text:
            return "2.0"
        return "2.0"
    if '"type": "bundle"' in text:
        return "2.0"
    return "unknown"

def parse_stix1(xml_bytes):
    root = ET.fromstring(xml_bytes)
    ns = {
        "stix": "http://docs.oasis-open.org/cti/ns/stix/core-1",
        "indicator": "http://docs.oasis-open.org/cti/ns/stix/indicator-1",
        "URIObject": "http://docs.oasis-open.org/cti/ns/cybox/objects/uri-2"
    }
    stix1_schema = {
     "STIX_Package": ["version","id","timestamp","Indicators","Incidents","Campaigns","Threat_Actors"],
     "Indicator": ["id","timestamp","Type","Description","Observable"],
     "Observable": ["id","Object","Title","Description"],
     "Object": ["Properties"],
     "URIObject": ["Value","condition","apply_condition","type"],
     "Incident": ["id","timestamp","Description","Time"],
     "TTP": ["id","Title","Description"],
     "Campaign": ["id","Title","Description"],
     "ThreatActor": ["id","Title","Description"]
    }
    top_id = root.get("id") or ""
    try:
        top_idn = top_id.split(":")[-1] if ":" in top_id else top_id
    except Exception:
        top_idn = top_id
    version = root.get("version") or ""
    modified_colln = []
    for indicator_elem in root.findall(".//stix:Indicator", ns):
        modified_dict = {
            "stix_version": "",
            "entity_type": "",
            "indicator_type": "",
            "description": "",
            "timestamp":"",
            "values": None,
            "validation" : False
        }
        valid_tags = []
        valid_attributes = []
        for inx in root.iter():
            clean = strip_ns(inx.tag)
            valid_tags.append(clean)
            for a in inx.attrib.keys():
                valid_attributes.append(a)
        tags_val = False
        attr_val = False
        for key, attributes in stix1_schema.items():
            if key in valid_tags:
                tags_val = True
                for at in attributes:
                    if at in valid_attributes:
                        attr_val = True
                    else:
                        attr_val = False
        if tags_val or attr_val:
            modified_dict["validation"] = True
        modified_dict["stix_version"] = version
        raw_id = indicator_elem.get("id") or ""
        idn = raw_id.split(":")[-1] if ":" in raw_id else raw_id
        timestamp = indicator_elem.get("timestamp") or ""
        modified_dict["entity_type"] = strip_ns(indicator_elem.tag)
        type_elem = indicator_elem.find(".//indicator:Type", ns)
        desc_elem = indicator_elem.find(".//indicator:Description", ns)
        value_elem = indicator_elem.find(".//URIObject:Value", ns)
        indicator_type = type_elem.text if type_elem is not None and type_elem.text else ""
        description = desc_elem.text if desc_elem is not None and desc_elem.text else ""
        values = value_elem.text.split("##comma##") if value_elem is not None and value_elem.text else []
        modified_dict["indicator_type"] = indicator_type
        modified_dict["description"] = description
        modified_dict["values"] = values
        modified_dict["timestamp"] = timestamp
        modified_colln.append(modified_dict)
    return modified_colln

def parse_stix2(item):
    stix2_validation_schema = {
        "bundle": {"required": ["type", "id", "objects"]},
        "common": {"required": ["type", "id", "created"]},
        "malware": {"required": ["name"]},
        "indicator": {"required": ["pattern", "valid_from", "labels"]},
        "relationship": {"required": ["source_ref", "target_ref", "relationship_type"]},
        "attack-pattern": {"required": ["name"]},
        "tool": {"required": ["name", "labels"]},
        "identity": {"required": ["name", "identity_class"]},
        "report": {"required": ["name", "published", "object_refs"]},
        "course-of-action": {"required": ["name"]}
    }
    root_obj = item.get("type")
    is_field = True if item.get("objects") else False
    typeof_obj = isinstance(item.get("objects"), list)
    ph1 = False
    ph2 = False
    ph3 = False
    ph0 = False
    if (root_obj == "bundle") and is_field and typeof_obj:
        ph1 = True
        if ("type" in item.keys()) and ("id" in item.keys()) and ("objects" in item.keys()):
            ph0 = True
            for _ in range(len(item["objects"])):
                if ("type" in item["objects"][_].keys()) and ("id" in item["objects"][_].keys()):
                    ph2 = True
                    obj_type = item["objects"][_]["type"]
                    if obj_type in stix2_validation_schema:
                        ph3 = True
                        for vals in stix2_validation_schema[obj_type]["required"]:
                            if vals not in item["objects"][_].keys():
                                ph3 = False
                                break
                else:
                    ph2 = False
        else:
            ph0 = False
    else:
        ph1 = False
    validation = False
    if ph0 and ph1 and ph2 and ph3:
        validation = True
    arr_of_data = []
    try:
        item_out = list(item.keys())
        item_in = list(item["objects"][0].keys()) if item.get("objects") and len(item["objects"])>0 else []
        merged_list = item_in + item_out
        for indice in range(len(item.get("objects", []))):
            modified_dict_20 = {
                "stix_version": "",
                "entity_type": "",
                "indicator_type": "",
                "description": "",
                "timestamp":"",
                "values": None,
                "validation": False
            }
            if not validation:
                continue
            else:
                modified_dict_20["validation"] = validation
            if ("stix_version" in merged_list) or ("spec_version" in merged_list) or ("version" in merged_list):
                modified_dict_20["stix_version"] = "2.1"
            else:
                modified_dict_20["stix_version"] = "2.0"
            obj = item["objects"][indice]
            modified_dict_20["entity_type"] = obj.get("type", "Couldn't find entity type")
            modified_dict_20["description"] = obj.get("description", "Description not found")
            modified_dict_20["timestamp"] = obj.get("created", None)
            name = obj.get("name")
            alias = obj.get("x_mitre_aliases") or []
            labels = obj.get("labels") or []
            if name:
                final = [name]
            elif alias:
                final = alias
            elif labels:
                final = labels if isinstance(labels, list) else [labels]
            else:
                final = [obj.get("type")]
            modified_dict_20["indicator_type"] = final
            refs = obj.get("external_references") or []
            er = []
            for r in refs:
                if isinstance(r, dict) and "external_id" in r:
                    er.append(r["external_id"])
                elif isinstance(r, dict) and "url" in r:
                    er.append(r["url"])
            name_list = [name] if name else []
            merged_values = name_list + (alias or []) + er
            modified_dict_20["values"] = merged_values
            arr_of_data.append(modified_dict_20)
    except Exception:
        pass
    return arr_of_data

def parse_stix(raw):
    version = detect_stix_version(raw)
    if version == "1.x":
        return parse_stix1(raw)
    try:
        if isinstance(raw, bytes):
            item = json.loads(raw)
        elif isinstance(raw, str):
            item = json.loads(raw)
        else:
            item = raw
    except Exception:
        return []
    return parse_stix2(item)
