#!/usr/bin/env python3
# Title         : mscp_yaml.py
# Description   : Functions to process YAML files
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

class YamlException(Exception):
    def __init__(self, value):
        self.value = value
    def __str__(self):
        return repr(self.value)
    def split(self, needle):
        return self.value.split(needle)

class Yaml:
    def __init__(self):
        self.versions = ["catalina", "monterey", "big sur"]

    def loadRules(self, location):
        rule_dict = {}
        if os.path.exists(location):
            for _mscp_rule in glob.glob(f'{location}/*/*.yaml'):
                _mscp_rule_filename = (os.path.basename(_mscp_rule))
                with open(_mscp_rule, "r") as f:
                    try:
                        rule_dict[_mscp_rule_filename] = yaml.load(f, Loader=yaml.SafeLoader)
                    except Exception as exc:
                        raise YamlException("Failed to Load {}".format(_mscp_rule)) from exc
        return rule_dict
    
    def compileRules(self, original_rules, custom_rules):
        """ Takes the orginal rules and the custom rules and returns a list of rule with usable values"""
        rule_list = []
        for rule in original_rules:
            record = {}
            for _key, _value in original_rules[rule].items():
                record[_key] = _value
            
            if rule in custom_rules:
                logger.info(f"Found custom rule for {rule}")
                for _key, _value in custom_rules[rule].items():
                    record[_key] = _value
            rule_list.append(record)
        
        # add any custom rules found
        for rule in custom_rules:
            if rule not in original_rules:
                logger.info(f"Found new custom rule for {rule}")
                record = {}
                for _key, _value in custom_rules[rule].items():
                    record[_key] = _value
                rule_list.append(record)
        
        return rule_list
