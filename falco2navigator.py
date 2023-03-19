#!/usr/bin/python3

import argparse
import json
import re
import sys
from pathlib import Path
from typing import Optional

from pydantic import BaseModel, validator
from ruamel.yaml import YAML

NAVIGATOR_COLOR_LIMIT = 3
NAVIGATOR_COLOR_FROM = "#fff7b3"
NAVIGATOR_COLOR_TO = "#ff6666"
NAVIGATOR_FILTER = ["Linux"]
NAVIGATOR_NAME = "Falco - Rules Coverage"
NAVIGATOR_LAYER = {
    "name": NAVIGATOR_NAME,
    "domain": "enterprise-attack",
    "hideDisabled": False,
    "sorting": 3,
    "filters": {"platforms": NAVIGATOR_FILTER},
    "versions": {
        "attack": "12",
        "navigator": "4.8.0",
        "layer": "4.4",
    },
    "layout": {
        "layout": "side",
        "showName": True,
        "showID": False,
        "showAggregateScores": True,
        "countUnscored": True,
        "aggregateFunction": "average",
    },
    "gradient": {
        "colors": [NAVIGATOR_COLOR_FROM, NAVIGATOR_COLOR_TO],
        "maxValue": NAVIGATOR_COLOR_LIMIT,
        "minValue": 0,
    },
}


class FalcoRule(BaseModel):
    enabled: Optional[bool]
    name: Optional[str]
    desc: Optional[str]
    condition: Optional[str]
    severity: Optional[str]
    techniques: Optional[list]

    @validator("techniques", pre=True)
    def filter_mitre_techniques(cls, techniques):
        if not techniques:
            return None
        result = []
        pattern = re.compile(r"^T\d{4}(\.\d{3})?$")
        for technique in techniques:
            if re.match(pattern, technique):
                result.append(technique)
        return result

    class Config:
        validate_assignment = True


def build_rawjson(rules: list, output: str):
    filename = Path(output)
    with open(filename, "w") as f:
        json.dump(rules, f, indent=2, default=dict)

    msgstr = 'INFO: Raw JSON file "{}" created'
    print(msgstr.format(filename.absolute()))


def build_navigator(rules: list, output: str):
    techniques = {}
    for rule in rules:
        for technique in rule.techniques:
            default = {"techniqueID": technique, "score": 0, "metadata": []}
            meta = {"name": rule.name, "value": rule.desc}
            techniques.setdefault(technique, default)
            techniques[technique]["score"] += 1
            techniques[technique]["metadata"].append(meta)

    layer = json.loads(json.dumps(NAVIGATOR_LAYER))
    layer["techniques"] = list(techniques.values())
    filename = Path(output)
    with open(filename, "w") as f:
        json.dump(layer, f, indent=2)

    msgstr = 'INFO: ATT&CK Navigator file "{}" created'
    print(msgstr.format(filename.absolute()))


def parse(ruleslist: list, enabled_only: bool):
    rules = {}
    result = []
    for rulefile in ruleslist:
        with open(rulefile, encoding="utf-8") as f:
            ruledata = YAML(typ="safe").load(f)

        for item in ruledata:
            if "rule" not in item.keys():
                continue
            rule = FalcoRule()
            rule.name = item["rule"]
            rule.desc = item.get("desc")
            rule.condition = item.get("condition")
            rule.severity = item.get("priority")
            rule.techniques = item.get("tags")
            rule.enabled = item.get("enabled")
            if baserule := rules.get(rule.name):
                baserule = baserule.dict(exclude_unset=True)
                newrule = rule.dict(exclude_unset=True, exclude_none=True)
                newrule = {**baserule, **newrule}
                rule = FalcoRule(**newrule)
            rules[rule.name] = rule

    msgstr = 'INFO: Rule "{}" processed'
    for rule in rules.values():
        if rule.enabled is None:
            rule.enabled = True
        if enabled_only and not rule.enabled:
            continue
        print(msgstr.format(rule.name))
        result.append(rule)
    return result


if __name__ == "__main__":
    parser = argparse.ArgumentParser()
    parser.add_argument("--process", default="enabled", choices=["all", "enabled"])
    parser.add_argument("--format", default="navigator", choices=["raw", "navigator"])
    parser.add_argument("-r", dest="rules", action="append", required=True)
    parser.add_argument("-o", dest="output", required=True)
    errstr = 'ERROR: "{}" {} location is incorrect or does not exist'

    args = parser.parse_args()
    ruleslist = []
    for rulepath in args.rules:
        rulepath = Path(rulepath)
        if rulepath.is_dir():
            for f in rulepath.glob("*.yml"):
                ruleslist.append(f)
            for f in rulepath.glob("*.yaml"):
                ruleslist.append(f)
        elif rulepath.is_file():
            ruleslist.append(rulepath)
        else:
            print(errstr.format(rulepath, "rule"), file=sys.stderr)
            exit(1)

    output = Path(args.output)
    if not output.parent.is_dir() or output.is_dir():
        print(errstr.format(output, "output"), file=sys.stderr)
        exit(1)

    enabled_only = args.process == "enabled"
    rules = parse(ruleslist, enabled_only)
    if args.format == "navigator":
        build_navigator(rules, args.output)
    elif args.format == "raw":
        build_rawjson(rules, args.output)
