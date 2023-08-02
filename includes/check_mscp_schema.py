#!/usr/bin/env python3
""" Evaluate yaml files for MSCP """

import sys
import yaml
from cerberus import Validator

# schema for rule files
rules_schema = {
    "id": {"required": True, "type": "string"},
    "title": {"required": True, "type": "string"},
    "discussion": {"required": True, "type": "string"},
    "check": {"required": True, "type": "string"},
    "result": {"required": False, "type": "dict"},
    "fix": {"required": True, "type": "string"},
    "references": {"required": True, "type": "dict", "schema": {
        "cce": {"required": True, "type": "list"},
        "cci": {"required": False, "type": "list"},
        "800-53r5": {"required": True, "type": "list"},
        "800-53r4": {"required": False, "type": "list"},
        "srg": {"required": False, "type": "list"},
        "disa_stig": {"required": False, "type": "list"},
        "800-171r2": {"required": False, "type": "list"},
        "cmmc": {"required": False, "type": "list"},
        "cis": {"required": False, "type": "dict", "schema":{
            "benchmark": {"required": True, "type": "list"},
            "controls v8": {"required": True, "type": "list"},
        }},
    }},
    "macOS": {"required": True, "type": "list"},
    "mobileconfig": {"required": True, "type": "boolean"},
    "mobileconfig_info": {"required": True, "nullable": True, "type": "dict"},
    "tags": {"required": True, "type": "list"},
    "severity": {"required": False, "type": "string"},
    "odv": {"required": False, "allow_unknown": True, "type": "dict", "schema":{
        "hint": {"required": True, "type": "string"},
        "recommended": {"required": True}
    }},
}

# schema for baseline files
baselines_schema = {
    "title": {"required": True, "type": "string"},
    "description": {"required": True, "type": "string"},
    "authors": {"required": True, "type": "string"},
    "parent_values": {"required": True, "type": "string"},
    "profile": {"required": True, "type": "list"}
}

rules_v = Validator(rules_schema)
baselines_v = Validator(baselines_schema)

error_files = []
for file in sys.argv[1:]:
    with open(file, "r", encoding='UTF-8') as conf_yaml:
        try:
            configuration = yaml.safe_load(conf_yaml)
        except yaml.YAMLError as err:
            print(f"ERROR: {file}")
            print(err)

    if file.startswith("baselines"):
        if baselines_v.validate(configuration):
            print(f"PASS: {file} meet the schema requriements")
        else:
            print(f"ERROR: {file}")
            print(baselines_v.errors)
            error_files.append(file)
    elif file.startswith("rules"):
        if "supplemental" in file:
            print(f"SKIPPED: {file}")
            continue
        if rules_v.validate(configuration):
            print(f"PASS: {file} meet the schema requriements")
        else:
            print(f"ERROR: {file}")
            print(rules_v.errors)
            error_files.append(file)

if len(error_files) > 0:
    sys.exit(1)
else:
    sys.exit(0)
