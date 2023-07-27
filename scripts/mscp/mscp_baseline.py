#!/usr/bin/env python3
# Title         : mscp_baseline.py
# Description   : Utilties to generate MSCP content
# Author        : Dan Brodjieski <brodjieski@gmail.com>
# Date          : 2022-06-16
# Version       : 0.1
# Notes         :

import yaml
import os
import glob
import logging

# Set up logger from main()
logger = logging.getLogger(__name__)

def section_title(section_name):
    titles = {
        "auth": "authentication",
        "audit": "auditing",
        "os": "os",
        "pwpolicy": "passwordpolicy",
        "icloud": "icloud",
        "sysprefs": "systempreferences",
        "srg": "srg",
        "system": "systemsettings"
    }
    if section_name in titles:
        return titles[section_name]
    else:
        return section_name

def build_section(section_name, rules, sub_section=False):
    section_yaml = {}
    section_yaml[section_name] = {}
    section_yaml[section_name]['rules'] = []
    for rule in rules:
        if sub_section:
            if rule.startswith(section_name):
                section_yaml[section_name]['rules'].append(rule)
        else:
            section_yaml[section_name]['rules'].append(rule)
    return section_yaml

def build_baseline(rules, platform, os, keyword, benchmark="recommended"):
    inherent_rules = []
    permanent_rules = []
    na_rules = []
    supplemental_rules = []
    other_rules = []
    sections = []
    baseline_yaml = {}

    for rule in rules:
        if "inherent" in rule['tags']:
            inherent_rules.append(rule['id'])
        elif "permanent" in rule['tags']:
            permanent_rules.append(rule['id'])
        elif "n_a" in rule['tags']:
            na_rules.append(rule['id'])
        elif "supplemental" in rule['tags']:
            supplemental_rules.append(rule['id'])
        else:
            if rule['id'] not in other_rules:
                other_rules.append(rule['id'])
            section_name = rule['id'].split("_")[0]
            if section_name not in sections:
                sections.append(section_name)

    baseline_yaml['title'] = f'{platform} {os}: Security Configuration - {keyword}'
    baseline_yaml['description'] = f'This guide describes the actions to take when securing a {platform} {os} system against the {keyword} baseline.'
    baseline_yaml['authors'] = '|===\n|Name|Organization\n|==='
    baseline_yaml['parent_values'] = benchmark
    baseline_yaml['profile'] = {}
    
    # sort the rules
    other_rules.sort()
    inherent_rules.sort()
    permanent_rules.sort()
    na_rules.sort()
    supplemental_rules.sort()


    if len(other_rules) > 0:
        
        for section in sections:
            section_yaml = build_section(section, other_rules, sub_section=True)
            baseline_yaml['profile'].update(section_yaml)
            # baseline_yaml['profile'][section_title(section)] = {}
            # baseline_yaml['profile'][section_title(section)]['rules'] = []
            # for rule in other_rules:
            #     if rule.startswith(section):
            #         baseline_yaml['profile'][section_title(section)]['rules'].append(rule)
    
    if len(inherent_rules) > 0:
        baseline_yaml['profile']['Inherent'] = {}
        baseline_yaml['profile']['Inherent']['rules'] = []
        for rule in inherent_rules:
            baseline_yaml['profile']['Inherent']['rules'].append(rule)

    if len(permanent_rules) > 0:
        baseline_yaml['profile']['Permanent'] = {}
        baseline_yaml['profile']['Permanent']['rules'] = []
        for rule in permanent_rules:
            baseline_yaml['profile']['Permanent']['rules'].append(rule)

    if len(na_rules) > 0:
        baseline_yaml['profile']['not_applicable'] = {}
        baseline_yaml['profile']['not_applicable']['rules'] = []
        for rule in na_rules:
            baseline_yaml['profile']['not_applicable']['rules'].append(rule)
    

    if len(supplemental_rules) > 0:
        baseline_yaml['profile']['Supplemental'] = {}
        baseline_yaml['profile']['Supplemental']['rules'] = []
        for rule in supplemental_rules:
            baseline_yaml['profile']['Supplemental']['rules'].append(rule)

    return baseline_yaml