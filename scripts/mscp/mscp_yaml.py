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

class MyDumper(yaml.Dumper):

    def increase_indent(self, flow=False, indentless=False):
        return super(MyDumper, self).increase_indent(flow, False)

def str_presenter(dumper, data):
    """configures yaml for dumping multiline strings
    Ref: https://stackoverflow.com/questions/8640959/how-can-i-control-what-scalar-form-pyyaml-uses-for-my-data"""
    if data.count('\n') > 0:  # check for multiline string
        return dumper.represent_scalar('tag:yaml.org,2002:str', data, style='|')
    return dumper.represent_scalar('tag:yaml.org,2002:str', data)

yaml.add_representer(str, str_presenter)
yaml.representer.SafeRepresenter.add_representer(str, str_presenter)

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

    def compileRules(self, original_rules, custom_rules, benchmark, platform, os_version):
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
            if self.fill_in_OS_specs(record, platform, os_version):
                rule_list.append(record)

        # add any new custom rules found that don't match with original library
        for rule in custom_rules:
            if rule not in original_rules:
                logger.info(f"Found new custom rule for {rule}")
                record = {}
                for k, v in custom_rules[rule].items():
                    record[k] = v
                self.fill_in_ODV(record, benchmark)
                if self.fill_in_OS_specs(record, platform, os_version):
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

            if 'result' in rule.keys():
                for result_value in rule['result']:
                    if "$ODV" in str(rule['result'][result_value]):
                        rule['result'][result_value] = odv

            if rule['mobileconfig_info']:
                for mobileconfig_type in rule['mobileconfig_info']:
                    if isinstance(rule['mobileconfig_info'][mobileconfig_type], dict):
                        for mobileconfig_value in rule['mobileconfig_info'][mobileconfig_type]:
                            if "$ODV" in str(rule['mobileconfig_info'][mobileconfig_type][mobileconfig_value]):
                                rule['mobileconfig_info'][mobileconfig_type][mobileconfig_value] = odv
    
    def fill_in_OS_specs(self, rule, platform, os_version):
        """Takes a rule and fills in any OS specific values for the supplied OS.  Default is the version of OS on the current system."""
        try:
            os_version_specs = rule["os_specifics"][platform][os_version]
        except KeyError:
            logging.info(f"fill_in_OS_specs:  Rule {rule['id']} has no values for OS {platform} {os_version}, skipping...")
            return False

        _included_keys = []
        for key, value in recursive_items(os_version_specs):
            _included_keys.append(key)

        if "references" in _included_keys:
            _included_keys.remove("references")
            for key in _included_keys:
                try:
                    rule['references'][key]=rule["os_specifics"][platform][os_version]['references'][key]
                except:
                    pass
            
        # process remaining keys
        for key in _included_keys:
            try:
                rule[key]=rule["os_specifics"][platform][os_version][key]
            except:
                pass
        
        return True
    
    def add_new_OS(self, rule, os_specs, newos, copy_stig):
        if copy_stig == "Y":
            stig = os_specs['references']['disa_stig']
        else:
            stig = []
        _specifics = { "references" :
        { "cce": [],
        "disa_stig": stig
        }
        }

        logging.info(f"Adding specifics for macOS {newos} for {rule['id']}")
        rule["os_specifics"]['macOS'][newos] = _specifics
        return
    
    def exportToYaml(self, name, record, outdir, nameispath=False):
        """Accept a name, record, and directory and safe properly formated YAML to it."""
        if not os.path.exists(outdir):
            os.makedirs(outdir)
        if nameispath:
            _outfile = name
        else:
            _outfile = os.path.join(outdir, name + '.yaml')
        
        logging.info(f"Writing YAML output for {name}")
        with open(_outfile, "w") as f:
            f.write("---\n")
            f.write(self.toYamlString(record, 0))
            f.write("\n")
        return

    def dumpToYaml(self, name, record, outdir, nameispath=False):
        """Accept a name, record, and directory and safe properly formated YAML to it."""
        if not os.path.exists(outdir):
            os.makedirs(outdir)
        if nameispath:
            _outfile = name
        else:
            _outfile = os.path.join(outdir, name + '.yaml')
        
        logging.info(f"Writing YAML output for {name}")
        with open(_outfile, "w") as f:
            yaml.dump(record,f, Dumper=MyDumper, sort_keys=False, width=float("inf"))
        return
    
    def toYamlString(self, obj_part, depth):
        """Returns a customized formatted YAML string of object passed into it, 
        a depth value is used to format element shifting."""
        if type(obj_part) is dict:
            _retval = ""
            for key, val in obj_part.items():
                if type(val) is dict:
                    if val == {}:
                        _retval = "{}{}{}: {{}}\n".format(_retval, " "*depth, key)
                    else:
                        _retval = "{}{}{}:\n{}".format(_retval, " "*depth, key, self.toYamlString(val, depth+2))
                elif type(val) is list:
                    #print(val)
                    _retval = "{}{}{}:{}".format(_retval, " "*depth, key, self.toYamlString(val, depth+2))
                else:
                    _retval = "{}{}{}:{}".format(_retval, " "*depth, key, self.toYamlString(val, depth+2))
            return _retval
        if type(obj_part) is list or type(obj_part) is tuple:
            if list(obj_part) == []:
                return " []\n"
            _retval = "\n"
            for element in list(obj_part):
                #print("{} {}".format(element, type(element)))
                if type(element) is dict:
                    _retval = "{}{}-{}".format(_retval, " "*(depth-2), self.toYamlString(element, depth+2))
                else:
                    _retval = "{}{}-{}".format(_retval, " "*depth, self.toYamlString(element, depth+2))
            return _retval
        if type(obj_part) is bool:
            if obj_part:
                return " |-\n{}True\n".format(" "*depth)
            else:
                return " |-\n{}False\n".format(" "*depth)

        if type(obj_part) is str or type(obj_part) is int or type(obj_part) is float:
            if str(obj_part) == "":
                return " \"\"\n"
            else:
                _split = str(obj_part).strip().split("\n")
                _indent = []
                for _s in _split:
                    _indent.append("{}{}".format(" "*depth, _s))
                return " |-\n{}\n".format("\n".join(_indent))
        else:
            print("could not process {} type {}".format(obj_part, type(obj_part)))
            return ""