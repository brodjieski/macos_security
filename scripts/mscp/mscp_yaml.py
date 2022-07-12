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

def recursive_items(dictionary):
    for key, value in dictionary.items():
        if type(value) is dict:
            yield (key, value)
            yield from recursive_items(value)
        else:
            yield (key, value)

class Yaml:
    def __init__(self):
        self.versions = ["catalina", "monterey", "big sur"]

    def loadRules(self, location):
        """Takes a location of rule files (expecting yaml) and returns a dict of found rules"""
        rule_dict = {}
        if os.path.exists(location):
            for mscp_rule in glob.glob(f"{location}/*/*.yaml"):
                mscp_rule_filename = os.path.basename(mscp_rule)
                logger.info(f"Found rule {mscp_rule}")
                with open(mscp_rule, "r") as f:
                    try:
                        rule_dict[mscp_rule_filename] = yaml.load(
                            f, Loader=yaml.SafeLoader
                        )
                    except Exception as exc:
                        raise YamlException(
                            "Failed to Load {}".format(mscp_rule)
                        ) from exc
        return rule_dict

    def compileRules(self, original_rules, custom_rules, benchmark, macos):
        """Takes the orginal rules and the custom rules and returns a list of rules with usable values"""
        rule_list = []
        
        # build list of rules from original library, overriding values from custom library
        for rule in original_rules:
            record = {}
            for k, v in original_rules[rule].items():
                record[k] = v

            if rule in custom_rules:
                logger.info(f"Found custom rule for {rule}")
                for k, v in custom_rules[rule].items():
                    logger.info(f"Overwriting value for {k} in {rule}")
                    record[k] = v
            self.fill_in_ODV(record, benchmark)
            if self.fill_in_OS_specs(record, macos):
                rule_list.append(record)

        # add any new custom rules found that don't match with original library
        for rule in custom_rules:
            if rule not in original_rules:
                logger.info(f"Found new custom rule for {rule}")
                record = {}
                for k, v in custom_rules[rule].items():
                    record[k] = v
                self.fill_in_ODV(record, benchmark)
                if self.fill_in_OS_specs(record, macos):
                    rule_list.append(record)

        return rule_list
    
    def fill_in_ODV(self, rule, benchmark):
        """Takes a rule and fills in the organizational defined values (ODV) for the supplied benchmark.  Default is 'recommended'."""
        fields_to_process = ['title', 'discussion', 'check', 'fix']
        _has_odv = False
        if "odv" in rule:
            try:
                odv = str(rule['odv'][benchmark])
                _has_odv = True
            except KeyError:
                logging.info(f"fill_in_ODV:  Rule {rule['id']} doesn't have benchmark value, using recommended")
                odv = str(rule['odv']['recommended'])
                _has_odv = True

        if _has_odv:
            for field in fields_to_process:
                if "$ODV" in rule[field]:
                    rule[field]=rule[field].replace("$ODV", odv)

            for result_value in rule['result']:
                if "$ODV" in str(rule['result'][result_value]):
                    rule['result'][result_value] = odv

            if rule['mobileconfig_info']:
                for mobileconfig_type in rule['mobileconfig_info']:
                    if isinstance(rule['mobileconfig_info'][mobileconfig_type], dict):
                        for mobileconfig_value in rule['mobileconfig_info'][mobileconfig_type]:
                            if "$ODV" in str(rule['mobileconfig_info'][mobileconfig_type][mobileconfig_value]):
                                rule['mobileconfig_info'][mobileconfig_type][mobileconfig_value] = odv
    
    def fill_in_OS_specs(self, rule, macos):
        """Takes a rule and fills in any OS specific values for the supplied OS.  Default is the version of OS on the current system."""
        try:
            macos_specs = rule["OS_specifics"]['macOS'][macos]
        except KeyError:
            logging.info(f"fill_in_OS_specs:  Rule {rule['id']} has no values for macOS {macos}, skipping...")
            return False

        _included_keys = []
        for key, value in recursive_items(macos_specs):
            _included_keys.append(key)

        if "references" in _included_keys:
            _included_keys.remove("references")
            for key in _included_keys:
                try:
                    rule['references'][key]=rule["OS_specifics"]['macOS'][macos]['references'][key]
                except:
                    pass
            
        # process remaining keys
        for key in _included_keys:
            try:
                rule[key]=rule["OS_specifics"]['macOS'][macos][key]
            except:
                pass
        
        return True