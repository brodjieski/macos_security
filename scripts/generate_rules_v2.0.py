#!/usr/bin/env python3
# filename: generate_guidance.py
# description: Process a given keyword, and output a baseline file

import os.path
import glob
import os
import yaml
import argparse
import pprint
from deepdiff import DeepDiff

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

def collect_rules(path):
    """Takes a baseline yaml file and parses the rules, returns a list of containing rules
    """
    all_rules = {}
    rule_ids = []
    #expected keys and references
    keys = ['mobileconfig',
            'macOS',
            'severity',
            'title',
            'check',
            'fix',
            'odv',
            'tags',
            'id',
            'references',
            'result',
            'discussion']
    references = ['disa_stig',
                  'cci',
                  'cce',
                  '800-53r4',
                  '800-53r5',
                  'srg']

    # '../rules/**/*.yaml'
    for rule in sorted(glob.glob(path,recursive=True)):
        with open(rule) as r:
            rule_yaml = yaml.load(r, Loader=yaml.SafeLoader)
        for key in keys:
            if key == "references":
                for reference in references:
                    try:
                        rule_yaml[key][reference]
                    except:
                        rule_yaml[key].update({reference: ["None"]})

        os_ver=rule.split("/")[3]

        if os_ver not in all_rules:
            all_rules[os_ver] = []
        
        if rule_yaml['id'] not in rule_ids:
            rule_ids.append(rule_yaml['id'])

        all_rules[os_ver].append(rule_yaml)
    

    return all_rules, rule_ids

def create_os_specifics(rule, fields):
    new_rule_yaml = {}
    
    try:
        version=rule['macOS'][0]
    except:
        version=rule['iOS'][0]
    new_rule_yaml = {}
    new_rule_yaml[version] = {}
    
    # process references
    new_rule_yaml[version]['references'] = {}
    new_rule_yaml[version]['references']['cce'] = rule['references']['cce']
    new_rule_yaml[version]['references']['disa_stig'] = rule['references']['disa_stig']
    new_rule_yaml[version]['references']['srg'] = rule['references']['srg']
    if 'sfr' in rule['references'].keys():
        new_rule_yaml[version]['references']['sfr'] = rule['references']['sfr']
    else:
        new_rule_yaml[version]['references']['sfr'] = ["N/A"]
    if 'cis' in rule['references'].keys():
        new_rule_yaml[version]['references']['cis'] = {}

        new_rule_yaml[version]['references']['cis']['benchmark'] = rule['references']['cis']['benchmark']

        new_rule_yaml[version]['references']['cis']['controls v8'] = rule['references']['cis']['controls v8']
    
    # process fields
    for field in fields:
        new_rule_yaml[version][field] = rule[field]
    #print(new_rule_yaml)
    return new_rule_yaml

def check_for_unique_fields(all_rules, rule_id):
    fields_to_compare=["discussion", "title", "check", "fix"]
    os_specific_fields = []
    bs_dict = {item['id']:item for item in all_rules['big_sur']}
    mont_dict = {item['id']:item for item in all_rules['monterey']}
    vent_dict = {item['id']:item for item in all_rules['ventura']}

    
    print(f'Comparing values for {rule_id}')
    for field in fields_to_compare:
        try:
            if bs_dict[rule_id][field] == mont_dict[rule_id][field] == vent_dict[rule_id][field]:
                continue
            else:
                os_specific_fields.append(field)
                #print(f'{field} is DIFFERENT across OS versions')
        except KeyError as e:
            print("rule not found in one of the OSs")
            print(e)
    


    return os_specific_fields

def keys_exists(element, *keys):
    '''
    Check if *keys (nested) exists in `element` (dict).
    '''
    if not isinstance(element, dict):
        raise AttributeError('keys_exists() expects dict as first argument.')
    if len(keys) == 0:
        raise AttributeError('keys_exists() expects at least two arguments, one given.')

    _element = element
    for key in keys:
        try:
            _element = _element[key]
        except KeyError:
            return False
    return True


def main():

    try:
        file_dir = os.path.dirname(os.path.abspath(__file__))
        parent_dir = os.path.dirname(file_dir)

        # stash current working directory
        original_working_directory = os.getcwd()

        # switch to the scripts directory
        os.chdir(file_dir)
    
        all_rules, rule_ids = collect_rules("../build/staging/**/*.yaml")
        
        build_path = os.path.join(parent_dir, 'build', 'rules', 'v2.0')
        if not (os.path.isdir(build_path)):
            try:
                os.makedirs(build_path)
            except OSError:
                print(f"Creation of the directory {build_path} failed")

    except IOError as msg:
        parser.error(str(msg))
    
    #check_for_unique_fields(all_rules, rule_ids)
    #pprint.pprint(all_rules)
    new_rules = {}

    for macos, rules in all_rules.items():
        for rule in rules:
            os_specific_fields = check_for_unique_fields(all_rules, rule['id'])
            
            os_specs=create_os_specifics(rule, os_specific_fields)

            rule['references']['cce'] = ['$OS_VALUE']
            rule['references']['disa_stig'] = ['$OS_VALUE']
            rule['references']['srg'] = ['$OS_VALUE']
            rule['references']['sfr'] = ['$OS_VALUE']

            try:
                rule['references']['cis']['benchmark'] = ['$OS_VALUE']
            except:
                pass
            try:
                rule['references']['cis']['controls v8'] = ['$OS_VALUE']
            except:
                pass

            for field in os_specific_fields:
                rule[field] = "$OS_VALUE"

            try:
                del rule['macOS']
                spec_var = "macOS"
            except:
                del rule['iOS']
                spec_var = "iOS"
            else:
                pass

            
            if not rule['id'] in new_rules.keys():
                new_rules[rule['id']] = rule
                new_rules[rule['id']]['os_specifics'] = {}
                new_rules[rule['id']]['os_specifics'][spec_var] = os_specs
            else:
                try:
                    new_rules[rule["id"]]["os_specifics"][spec_var].update(os_specs)
                except KeyError:
                    new_rules[rule['id']]['os_specifics'][spec_var] = os_specs
                
                current_tags=rule['tags']
                new_tags=new_rules[rule["id"]]["tags"]
                combined_tags=current_tags + list(set(new_tags) - set(current_tags))
                new_rules[rule["id"]]["tags"]=combined_tags

    #pprint.pprint(new_rules)




    for name, rule in new_rules.items():
        nr_filename = f'{name}.yaml'
        nr_folder = name.split("_")[0]
        nr_build_path = os.path.join(build_path, nr_folder)
        if not os.path.exists(nr_build_path):
            os.makedirs(nr_build_path)
        nr_path = os.path.join(nr_build_path, nr_filename)
 
        with open(nr_path, 'w') as file:
            yaml.dump(rule, file, Dumper=MyDumper, sort_keys=False, width=float("inf")) 
      
    # finally revert back to the prior directory
    os.chdir(original_working_directory)

if __name__ == "__main__":
    main()
