#!/usr/bin/env python3
# Title         : MSCP_TEMPLATE.py
# Description   : Basic template that loads the rule database and sets up data for processing
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
#import platform

# import mscp modules
sys.path.append(os.path.dirname(os.path.abspath(__file__)))
import mscp

def main():

    baseline_rules = []
    
    for rule in rule_list:
        if options.keyword in rule['tags']:
            baseline_rules.append(rule)
    
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