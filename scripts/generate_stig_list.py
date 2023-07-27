#!/usr/bin/env python3
# Title         : generate_stig_list.py
# Description   : Script to generate list of files with STIG references for a given Platform/OS
# Author        : Dan Brodjieski <brodjieski@gmail.com>
# Date          : 
# Version       : 1.0
# Notes         : 
# 

import sys
import os.path
import os
import pprint
from optparse import OptionParser
import logging
import yaml

# import mscp modules
sys.path.append(os.path.dirname(os.path.abspath(__file__)))
import mscp

def main():
    _repo_path = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
    build_path = os.path.join(_repo_path, "build", "rules", "new_stig")
    baseline_rules = []
    
    for rule in rule_list:
        if options.keyword in rule['tags']:
            baseline_rules.append(rule["references"]["disa"]["disa_stig"][0])
            #print(f'{rule["references"]["disa"]["disa_stig"][0]} - {rule["id"]}')
    
    _stig_rules={}
    with open("./build/staging/stig.yaml", "r") as f:
        try:
            _stig_rules = yaml.load(
                f, Loader=yaml.SafeLoader
            )
        except Exception as exc:
            raise YamlException(
                "Failed to Load {}".format("./build/staging/stig.yaml")
            ) from exc
    for _s in _stig_rules:
        if _s['version'] not in baseline_rules:
            if "SFR ID" in _s['description']:
                sfr=_s['description'].split("SFR ID: ")[1]
            else:
                sfr = "N/A"
            new_rule={}
            new_rule['id'] = _s['title'].replace(" ", "_")
            new_rule['title'] = _s["title"]
            new_rule['discussion'] = _s["description"]
            new_rule['check'] = ""
            new_rule['fix'] = "This is implemented by a Configuration Profile"
            new_rule['references'] = {}
            new_rule['references']['cce'] = ["N/A"]
            new_rule['references']['cci'] = _s['cci'].split(",")
            new_rule['references']['800-53r5'] = _s['nist800_53'].split(",")
            new_rule['references']['sfr'] = [sfr]
            new_rule['references']['disa_stig'] = [_s['version']]
            new_rule['references']['800-171r2'] = ["N/A"]
            new_rule['references']['cis'] = {}
            new_rule['references']['cis']['benchmark'] = ["N/A"]
            new_rule['references']['cis']['controls'] = ["N/A"]
            new_rule['iOS'] = ['16.0']
            new_rule['tags'] = ["ios", "stig"]
            new_rule['severity'] = _s['severity']
            new_rule['mobileconfig'] = "true"
            new_rule['mobileconfig_info'] = {}
            new_rule['mobileconfig_info']["payload_domain"] = {}
            new_rule['mobileconfig_info']["payload_domain"]["key"] = "value"

            _yaml.dumpToYaml(f'{_s["version"]}', new_rule, build_path)

    
if __name__ == "__main__":
    # Configure command line arguments
    _usage = "usage: %prog [options]"
    parser = OptionParser(_usage)

    # Platform values
    parser.add_option("-v", action="count", dest='verbosity', default=1, help="Enable verbose logging, add additonal 'v' to increase level")

    # Supplied benchmark
    parser.add_option("-b", action="store", dest='benchmark', default="recommended", help="Use the organization defined values from the supplied benchmark, defaults to recommended values")
    
    # Supplied platform
    parser.add_option("-k", action="store", dest='keyword', default="", help="Build the baseline based off of the supplied keyword")

    # Supplied platform
    parser.add_option("-p", action="store", dest='os_platform', default="macOS", help="Build the compliance info for the specified platform, defaults to macOS")

    # Supplied OS version
    parser.add_option("-o", action="store", dest='os_version', default="13.0", help="Build the compliance info for the specified OS version, defaults to currently running OS")
      
    # Process command line
    (options, args) = parser.parse_args()

    # Pull in the yaml functions
    _yaml = mscp.Yaml()

    # Setting up the rules path relative to scripts (assuming we are in the ./scripts folder)
    _repo_path = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))

    _rules_path = os.path.join(_repo_path, "rules")
    _custom_rules_path = os.path.join(_repo_path, "custom")

    # Set up logging
    if options.verbosity >= 4:
        _level = logging.DEBUG
    elif options.verbosity >= 3:
        _level = logging.INFO
    elif options.verbosity >= 2:
        _level = logging.WARNING
    elif options.verbosity >1:
        _level = logging.ERROR
    else:
        _level = logging.CRITICAL
    logging.basicConfig(level=_level)

    # build rules
    ruleset = _yaml.loadRules(_rules_path)
    custom_ruleset = _yaml.loadRules(_custom_rules_path)

    platform_rules = _yaml.getPlatformRules(ruleset, options.os_platform, options.os_version)

    logging.debug("\n".join(["**** RULESET ****", pprint.pformat(ruleset, indent=1, sort_dicts=False), "**** RULESET ****"]))
    logging.debug("\n".join(["**** CUSTOM RULESET ****", pprint.pformat(custom_ruleset, indent=1, sort_dicts=False), "**** CUSTOM RULESET ****"]))

    # merge original and custom rules for entire list in db
    rule_list = _yaml.compileRules(platform_rules, custom_ruleset, options.benchmark, options.os_platform, options.os_version)

    ### rule_list now contains the full library of rules including custom rule files found
    ### ODV values are included
    ### OS specific details are included
    ### begin processing within main() above
    
    main()