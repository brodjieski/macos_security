#!/usr/bin/env python3
# filename: mscp_utils.py
# description: Common utility functions for macOS Security Compliance Project scripts

import os
import glob
import yaml
from typing import Dict, List, Any, Optional, Union


class MacSecurityRule:
    """Class to represent a macOS security rule"""
    
    def __init__(self, title: str, rule_id: str, severity: str, discussion: str, 
                 check: str, fix: str, cci: List[str], cce: List[str], 
                 nist_controls: List[str], disa_stig: List[str], srg: List[str], 
                 odv: Dict[str, Any], tags: List[str], result_value: Any,
                 mobileconfig: Optional[str] = None, mobileconfig_info: Optional[Dict[str, Any]] = None):
        self.rule_title = title
        self.rule_id = rule_id
        self.rule_severity = severity
        self.rule_discussion = discussion
        self.rule_check = check
        self.rule_fix = fix
        self.rule_cci = cci
        self.rule_cce = cce
        self.rule_80053r4 = nist_controls
        self.rule_disa_stig = disa_stig
        self.rule_srg = srg
        self.rule_odv = odv
        self.rule_result_value = result_value
        self.rule_tags = tags
        self.rule_mobileconfig = mobileconfig
        self.rule_mobileconfig_info = mobileconfig_info

    def create_asciidoc(self, adoc_rule_template):
        """Pass an AsciiDoc template as file object to return formatted AsciiDOC"""
        rule_adoc = ""
        rule_adoc = adoc_rule_template.substitute(
            rule_title=self.rule_title,
            rule_id=self.rule_id,
            rule_severity=self.rule_severity,
            rule_discussion=self.rule_discussion,
            rule_check=self.rule_check,
            rule_fix=self.rule_fix,
            rule_cci=self.rule_cci,
            rule_80053r4=self.rule_80053r4,
            rule_disa_stig=self.rule_disa_stig,
            rule_srg=self.rule_srg,
            rule_result=self.rule_result_value
        )
        return rule_adoc


def get_rule_yaml(rule_file: str, custom: bool = False) -> Dict[str, Any]:
    """Takes a rule file, checks for a custom version, and returns the yaml for the rule
    
    Args:
        rule_file: Path to the rule file
        custom: Whether to use custom rules
        
    Returns:
        A dictionary containing the rule YAML data
    """
    resulting_yaml = {}
    names = [os.path.basename(x) for x in glob.glob('../custom/rules/**/*.y*ml', recursive=True)]
    file_name = os.path.basename(rule_file)

    if custom:
        print(f"Custom settings found for rule: {rule_file}")
        try:
            override_path = glob.glob('../custom/rules/**/{}'.format(file_name), recursive=True)[0]
        except IndexError:
            override_path = glob.glob('../custom/rules/{}'.format(file_name), recursive=True)[0]
        with open(override_path) as r:
            rule_yaml = yaml.load(r, Loader=yaml.SafeLoader)
    else:
        with open(rule_file) as r:
            rule_yaml = yaml.load(r, Loader=yaml.SafeLoader)

    try:
        og_rule_path = glob.glob('../rules/**/{}'.format(file_name), recursive=True)[0]
    except IndexError:
        # assume this is a completely new rule
        og_rule_path = glob.glob('../custom/rules/**/{}'.format(file_name), recursive=True)[0]

    # get original/default rule yaml for comparison
    with open(og_rule_path) as og:
        og_rule_yaml = yaml.load(og, Loader=yaml.SafeLoader)
    og.close()

    for yaml_field in og_rule_yaml:
        try:
            if og_rule_yaml[yaml_field] == rule_yaml[yaml_field]:
                resulting_yaml[yaml_field] = og_rule_yaml[yaml_field]
            else:
                resulting_yaml[yaml_field] = rule_yaml[yaml_field]
                if 'customized' in resulting_yaml:
                    resulting_yaml['customized'].append(f"customized {yaml_field}")
                else:
                    resulting_yaml['customized'] = [f"customized {yaml_field}"]
        except KeyError:
            resulting_yaml[yaml_field] = og_rule_yaml[yaml_field]

    return resulting_yaml


def collect_rules(rules_glob_pattern: str = '../rules/**/*.y*ml') -> List[MacSecurityRule]:
    """Collects and processes all rules
    
    Args:
        rules_glob_pattern: Glob pattern to search for rules
        
    Returns:
        A list of MacSecurityRule objects
    """
    all_rules = []
    # expected keys and references
    keys = ['mobileconfig', 'macOS', 'severity', 'title', 'check', 'fix', 'odv', 
            'tags', 'id', 'references', 'result', 'discussion']
    references = ['disa_stig', 'cci', 'cce', '800-53r4', 'srg']

    for rule in sorted(glob.glob(rules_glob_pattern, recursive=True)) + sorted(glob.glob('../custom/rules/**/*.y*ml', recursive=True)):
        rule_yaml = get_rule_yaml(rule, custom=False)
        for key in keys:
            try:
                rule_yaml[key]
            except:
                rule_yaml.update({key: "missing"})
            if key == "references":
                for reference in references:
                    try:
                        rule_yaml[key][reference]
                    except:
                        rule_yaml[key].update({reference: ["None"]})

        all_rules.append(MacSecurityRule(
            rule_yaml['title'].replace('|', '\\|'),
            rule_yaml['id'].replace('|', '\\|'),
            rule_yaml['severity'].replace('|', '\\|'),
            rule_yaml['discussion'].replace('|', '\\|'),
            rule_yaml['check'].replace('|', '\\|'),
            rule_yaml['fix'].replace('|', '\\|'),
            rule_yaml['references']['cci'],
            rule_yaml['references']['cce'],
            rule_yaml['references']['800-53r4'],
            rule_yaml['references']['disa_stig'],
            rule_yaml['references']['srg'],
            rule_yaml['odv'],
            rule_yaml['tags'],
            rule_yaml['result'],
            rule_yaml['mobileconfig'],
            rule_yaml['mobileconfig_info']
        ))

    return all_rules


def get_controls(all_rules: List[MacSecurityRule]) -> List[str]:
    """Extracts all unique controls from a list of rules
    
    Args:
        all_rules: List of MacSecurityRule objects
        
    Returns:
        List of unique control identifiers
    """
    all_controls = []
    for rule in all_rules:
        for control in rule.rule_80053r4:
            if control not in all_controls:
                all_controls.append(control)

    all_controls.sort()
    return all_controls


def load_yaml_file(file_path: str) -> Dict[str, Any]:
    """Safely load a YAML file
    
    Args:
        file_path: Path to the YAML file
        
    Returns:
        Dictionary containing the YAML data
    """
    try:
        with open(file_path) as f:
            return yaml.load(f, Loader=yaml.SafeLoader)
    except Exception as e:
        print(f"Error loading YAML file {file_path}: {e}")
        return {}


def section_title(section_name: str, platform: str) -> str:
    """Converts a section name to a display title
    
    Args:
        section_name: The raw section name
        platform: The platform string
        
    Returns:
        Formatted section title
    """
    os = platform.split(':')[2]
    titles = {
        "auth": "authentication",
        "audit": "auditing",
        "os": os,
        "pwpolicy": "passwordpolicy",
        "icloud": "icloud",
        "sysprefs": "systempreferences",
        "system_settings": "systemsettings",
        "sys_prefs": "systempreferences",
        "srg": "srg"
    }

    if section_name in titles:
        return titles[section_name]
    else:
        return section_name


def available_tags(all_rules: List[MacSecurityRule]) -> List[str]:
    """Get all unique tags from rules
    
    Args:
        all_rules: List of MacSecurityRule objects
        
    Returns:
        List of unique tags
    """
    all_tags = []
    for rule in all_rules:
        for tag in rule.rule_tags:
            all_tags.append(tag)

    available_tags = []
    for tag in all_tags:
        if tag not in available_tags:
            available_tags.append(tag)
    
    available_tags.append("all_rules")
    available_tags.sort()
    
    return available_tags