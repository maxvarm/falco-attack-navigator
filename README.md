# Falco Rules to MITRE ATT&CK Navigator

This repository contains a tiny **Python** script that exports **Falco** YAML rulefiles to **ATT&CK Navigator** format. It can be useful to determine overall **MITRE** coverage and have a picture of what rules to develop further.

The script looks for defined MITRE techniques in **"tags"** field, supports merging multipe YAML files, and knows how to handle disabled rules. Please see the **examples** folder or **usage** section for more details. You can read more about Falco and MITRE here:

-   https://mitre-attack.github.io/attack-navigator/
-   https://attack.mitre.org/matrices/enterprise/linux/
-   https://falco.org/docs/rules/basic-elements/#advanced-rule-syntax

## Usage

Basic export of prebuilt Falco rules. You can upload and review the results in Navigator UI.

```bash
git clone https://github.com/maxvarm/falco-attack-navigator
cd falco-attack-navigator
pip3 install -r requirements.txt

python3 falco2navigator.py -r examples/falco_rules.yaml -o basic-layout.json
```

Merge of multiple rules into one Navigator file. You can define the whole folder too.

```bash
python3 falco2navigator.py -r default.yaml -r local.yaml -r rules.d/ -o combined-layout.json
```

Include disabled rules in results and create raw JSON file rather than Navigator-formatted.

```bash
python3 falco2navigator.py -r examples/falco_rules.yaml -o raw-results.json --process=all --format=raw
```
