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

    def compileRules(self, original_rules, custom_rules):
        """Takes the orginal rules and the custom rules and returns a list of rule with usable values"""
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
            rule_list.append(record)

        # add any new custom rules found that don't match with original library
        for rule in custom_rules:
            if rule not in original_rules:
                logger.info(f"Found new custom rule for {rule}")
                record = {}
                for k, v in custom_rules[rule].items():
                    record[k] = v
                rule_list.append(record)

        return rule_list
