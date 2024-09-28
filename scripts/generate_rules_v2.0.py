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
from collections import defaultdict


class MyDumper(yaml.Dumper):

    def increase_indent(self, flow=False, indentless=False):
        return super(MyDumper, self).increase_indent(flow, False)

def str_presenter(dumper, data):
    """configures yaml for dumping multiline strings
    Ref: https://stackoverflow.com/questions/8640959/how-can-i-control-what-scalar-form-pyyaml-uses-for-my-data"""
    clean_data = data.replace(" \n", "\n")
    if clean_data.count('\n') > 0:  # check for multiline string
        return dumper.represent_scalar('tag:yaml.org,2002:str', clean_data, style='|')
    return dumper.represent_scalar('tag:yaml.org,2002:str', clean_data)

yaml.add_representer(str, str_presenter)
yaml.representer.SafeRepresenter.add_representer(str, str_presenter)    

def flatten_dict(d, parent_key='', sep='.'):
    """
    Flattens a nested dictionary.
    """
    items = []
    for k, v in d.items():
        new_key = f"{parent_key}{sep}{k}" if parent_key else k
        if isinstance(v, dict):
            items.extend(flatten_dict(v, new_key, sep=sep).items())
        else:
            items.append((new_key, v))
    return dict(items)

def get_unique_value_keys(dict_list):
    """
    Takes a list of dictionaries and returns keys with unique values across all dictionaries.
    """
    # Flatten all dictionaries in the list
    flat_dicts = [flatten_dict(d) for d in dict_list]

    # Collect values for each key
    key_to_values = defaultdict(set)
    for flat_dict in flat_dicts:
        for key, value in flat_dict.items():
            key_to_values[key].add(value)

    # Find keys with unique values
    unique_keys = []
    for key, values in key_to_values.items():
        if len(values) == len(dict_list):
            unique_keys.append(key)

    return unique_keys

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
                  '800-171r2',
                  'srg',
                  'sfr',
                  'cis',
                  'cmmc']

    nist_refs = ['cce', '800-53r4', '800-53r5', '800-171r2']
    disa_refs = ['disa_stig', 'cci', 'srg', 'sfr']
    cis_refs = ['benchmark', 'controls v8']

    # '../rules/**/*.yaml'
    os_order = ['sequoia', 'sonoma', 'ventura', 'monterey', 'big_sur', 'catalina', 'ios_18', 'ios_17', 'ios_16', 'visionos']
    working_rules = glob.glob(path,recursive=True)
    working_rules.sort(key=lambda x: x.split("/")[2])
    new_os_order = []
    for _os in os_order:
        for _r in working_rules:
            if _os in _r:
                new_os_order.append(_r)

    
    # pprint.pprint(new_os_order)
    for rule in new_os_order:
        with open(rule) as r:
            rule_yaml = yaml.load(r, Loader=yaml.SafeLoader)
        for key in keys:
            if key == "references":
                for reference in references:
                    if reference == 'cis':
                        if "cis" in rule_yaml["references"].keys():
                            for _r, _s in rule_yaml[key][reference].items():
                                if "N/A" in _s:
                                    print(f'removing N/A from {_r}')
                                    del(rule_yaml[key][reference][_r])
                                    print(rule_yaml)
                                    break
                    try:
                        rule_yaml[key][reference]
                        if "N/A" in rule_yaml[key][reference]:
                            del(rule_yaml[key][reference])
                    except:
                        #rule_yaml[key].update({reference: ["None"]})
                        pass
        
        rebuilt_refs = {}
        rebuilt_refs['nist'] = {}
        rebuilt_refs['disa'] = {}
        rebuilt_refs['cis'] = {}
        for _r in references:
            if _r in rule_yaml['references'].keys():
                if _r in nist_refs:
                    rebuilt_refs['nist'][_r] = rule_yaml['references'][_r]
                elif _r in disa_refs:
                    rebuilt_refs['disa'][_r] = rule_yaml['references'][_r]
                elif _r in cis_refs:
                    rebuilt_refs['cis'][_r] = rule_yaml['references'][_r]
                else:
                    rebuilt_refs[_r] = rule_yaml['references'][_r]
        
        rule_yaml['references'] = rebuilt_refs


        os_ver=rule.split("/")[2]
        if os_ver not in all_rules:
            all_rules[os_ver] = []
        
        if rule_yaml['id'] not in rule_ids:
            rule_ids.append(rule_yaml['id'])

        all_rules[os_ver].append(rule_yaml)
    
    # pprint.pprint(all_rules)
    return all_rules, rule_ids

def recursive_items(dictionary):
    for key, value in dictionary.items():
        if type(value) is dict:
            yield from recursive_items(value)
        else:
            yield (key, value)

def versionMap(version):
    versionDict={
        "13.0" : "Ventura",
        "12.0" : "Monterey",
        "11.0" : "Big_Sur",
        "10.15" : "Catalina",
        "14.0" : "Sonoma",
        "15.0" : "Sequoia",
        "16.0" : "iOS16",
        "17.0" : "iOS17",
        "18.0" : "iOS18",
        "2.0" : "visionOS2"
    }
    if version in versionDict.keys():
        return versionDict[version]
    else:
        return version

def approach1Fn(d):
    val = []
 
    for v in d.values():
        if isinstance(v, dict):
            val.extend(approach1Fn(v))
 
        elif isinstance(v, list):
            for i in v:
                if isinstance(i, dict):
                    val.extend(approach1Fn(i))
                else:
                    val.append(i)
        else:
            val.append(v)
    return val

def create_os_specifics(rule, fields):
    new_rule_yaml = {}
    
    if "macOS" in rule.keys():
        version=rule['macOS'][0]
    elif "iOS" in rule.keys():
        version=rule['iOS'][0]
    elif "ios" in rule.keys():
        version=rule['ios'][0]
    elif "macos" in rule.keys():
        version=rule['macos'][0]
    elif "visionOS" in rule.keys():
        version=rule['visionOS'][0]
    elif "visionos" in rule.keys():
        version=rule['visionos'][0]
    else:
        return {}
    
    version=versionMap(version)
    new_rule_yaml = {}
    new_rule_yaml[version] = {}
    
    # process references
    excluded_refs = ["800-53r5", "800-53r4", "800-171r2", "cmmc", "cci", "srg", "controls v8", "sfr"]

    new_rule_yaml[version]['references'] = {}
    
    top_level_refs = ["nist", "disa", "cis"]

    for tlr in top_level_refs:
        # print(rule)
        new_rule_yaml[version]['references'][tlr] = {}
        if tlr in rule['references'].keys():
            for _k, _v in rule['references'][tlr].items():
                if _k in excluded_refs:
                    continue
                if isinstance(_v, list):
                    if not _v == ['N/A']:
                        new_rule_yaml[version]["references"][tlr][_k] = _v
                
                elif isinstance(_v, dict):
                    new_rule_yaml[version]["references"][tlr][_k] = {}
                    for _kk, _vv in _v.items():
                        if isinstance(_vv, list):
                            if not _vv == ['N/A']:
                                new_rule_yaml[version]["references"][tlr][_k][_kk] = _vv
                        
                        elif isinstance(_vv, dict):
                            if not _vv == ['N/A']:
                                new_rule_yaml[version]["references"][tlr][_k][_kk] = _vv
        if new_rule_yaml[version]['references'][tlr] == {}:
            del(new_rule_yaml[version]['references'][tlr])

    
    
    # new_rule_yaml[version]['references']['cce'] = rule['references']['cce']
    # new_rule_yaml[version]['references']['disa_stig'] = rule['references']['disa_stig']
    # new_rule_yaml[version]['references']['srg'] = rule['references']['srg']
    # if 'sfr' in rule['references'].keys():
    #     new_rule_yaml[version]['references']['sfr'] = rule['references']['sfr']
    # # else:
    # #     new_rule_yaml[version]['references']['sfr'] = ["N/A"]
    # if 'cis' in rule['references'].keys():
    #     new_rule_yaml[version]['references']['cis'] = {}

    #     new_rule_yaml[version]['references']['cis']['benchmark'] = rule['references']['cis']['benchmark']

    #     new_rule_yaml[version]['references']['cis']['controls v8'] = rule['references']['cis']['controls v8']

    # process fields
    for field in fields:
        if not field == "references":
            new_rule_yaml[version][field] = rule[field].replace(' \n', '\n')
    
    found_valid = False
    for _f in approach1Fn(new_rule_yaml[version]['references']):
        if not _f == 'None' and not _f == "N/A":
             found_valid = True
    
    if not found_valid:
        # print(f'removing {version} specifics from {rule["title"]}')
        del(new_rule_yaml[version])
    # print(new_rule_yaml)
    return new_rule_yaml

def check_for_unique_fields(dictionaries_to_compare, ref_fields, rule_id):
    os_specific_fields = []
    
    for os in dictionaries_to_compare:
        if rule_id not in os.keys():
            print(f'{rule_id} not in all OSs ... ')
            os_specific_fields.append("references")
            return os_specific_fields
    #fields_to_compare=["discussion", "title", "check", "fix"]
    fields_to_compare=[]
    
    
    
    
    # pprint.pprint(dictionaries_to_compare)
    for field in fields_to_compare:
        try:
            field_values = [d[rule_id][field] for d in dictionaries_to_compare if field in d[rule_id]]
            if all(x == field_values[0] for x in field_values):
                # print(f'{field} is the same across all for {rule_id}')
                continue
            else:
                # print(f'{field} is the DIFFERENT across all for {rule_id}')
                os_specific_fields.append(field)
                # print(f'{field} is DIFFERENT across OS versions')
        except KeyError as e:
            # print("rule not found in one of the OSs")
            pass
    

    try:
        reference_dicts = [d[rule_id]["references"] for d in dictionaries_to_compare if "references" in d[rule_id]]
        
        # pprint.pprint(reference_dicts)
        unique_keys = get_unique_value_keys(reference_dicts)
        print("Keys with unique values:", unique_keys)
    except:
        pass


    # for field in ref_fields:
    #     print(dictionaries_to_compare[0][rule_id]['references'])
        # try:
        #     field_values = [d[rule_id][field] for d in dictionaries_to_compare if field in d[rule_id]]
        #     if all(x == field_values[0] for x in field_values):
        #         print(f'{field} is the same across all for {rule_id}')
        #         continue
        #     else:
        #         print(f'{field} is the DIFFERENT across all for {rule_id}')
        #         os_specific_fields.append(field)
        #         # print(f'{field} is DIFFERENT across OS versions')
        # except KeyError as e:
        #     # print("rule not found in one of the OSs")
        #     pass
    
    # try:        
    #     pprint.pprint(sonoma_dict[rule_id]["references"])
    # except KeyError as e:
    #     print(f'{rule_id} does exists for OS')

    os_specific_fields.append("references")
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

    file_dir = os.path.dirname(os.path.abspath(__file__))
    parent_dir = os.path.dirname(file_dir)

    # stash current working directory
    original_working_directory = os.getcwd()

    # switch to the scripts directory
    os.chdir(file_dir)

    all_rules, rule_ids = collect_rules("../_work/**/*.yaml")
    
    build_path = os.path.join(parent_dir, 'build', 'rules', 'v2.0')
    if not (os.path.isdir(build_path)):
        try:
            os.makedirs(build_path)
        except OSError:
            print(f"Creation of the directory {build_path} failed")
    
    #check_for_unique_fields(all_rules, rule_ids)
    new_rules = {}
    ref_fields = []
    for key, value in recursive_items(all_rules):
        for _rule in value:
            for ref_key, ref_val in recursive_items(_rule["references"]):
                if ref_key not in ref_fields:
                    ref_fields.append(ref_key)
    
    # build OS specific dictionaries
    bs_dict = {item['id']:item for item in all_rules['big_sur']}
    mont_dict = {item['id']:item for item in all_rules['monterey']}
    vent_dict = {item['id']:item for item in all_rules['ventura']}
    sonoma_dict = {item['id']:item for item in all_rules['sonoma']}
    seq_dict = {item['id']:item for item in all_rules['sequoia']}
    vision_dict = {item['id']:item for item in all_rules['visionos']}
    ios16_dict = {item['id']:item for item in all_rules['ios_16']}
    ios17_dict = {item['id']:item for item in all_rules['ios_17']}
    ios18_dict = {item['id']:item for item in all_rules['ios_18']}

    dictionaries_to_compare = [bs_dict, mont_dict, vent_dict, sonoma_dict, seq_dict, vision_dict, ios16_dict, ios17_dict, ios18_dict]
    
    new_refs = {}
    new_refs['nist'] = {}
    new_refs['disa'] = {}
    new_refs['cis'] = {}

    platforms = all_rules.keys()

    
    # print(all_rules)
    # for rule in rule_ids:
    #     for platform in platforms:
    #         if rule in all_rules[platform].keys():
    #             print(f'{rule} in {platform}')

    for macos, rules in all_rules.items():
        

        for rule in rules:
            os_specific_fields = check_for_unique_fields(dictionaries_to_compare, ref_fields, rule['id'])
            os_specs=create_os_specifics(rule, os_specific_fields)

            for field in os_specific_fields:
                if field == "references":
                    for key, value in recursive_items(os_specs):
                        try:
                            if key == "cce":
                                new_refs['nist']['cce'] = '$OS_VALUE'
                            if key == "disa_stig":
                                new_refs['disa']['disa_stig'] = '$OS_VALUE'
                            if key == "srg":
                                new_refs['disa']['srg'] = rule['references']['srg']
                            if key == "sfr":
                                new_refs['disa']['sfr'] = rule['references']['sfr']
                            if key == "cci":
                                new_refs['disa']['cci'] = rule['references']['cci']
                            if key == "800-53r5":
                                new_refs['nist']['800-53r5'] = rule['references']['800-53r5']
                            if key == "800-53r4":
                                new_refs['nist']['800-53r4'] = value
                            if key == "benchmark":
                                new_refs['cis']['benchmark'] = "$OS_VALUE"
                            
                            if key == "controls v8":
                                new_refs['cis']['controls v8'] = rule['references']['cis']['controls v8']
                        except:
                            pass
                else:
                    rule[field] = "$OS_VALUE"
            
            if '800-53r5' in rule['references']['nist']:
                new_refs['nist']['800-53r5'] = rule['references']['nist']['800-53r5']
            if '800-53r4' in rule['references']['nist']:
                new_refs['nist']['800-53r4'] = rule['references']['nist']['800-53r4']
            if 'cci' in rule['references']['disa']:
                new_refs['disa']['cci'] = rule['references']['disa']['cci']
            if 'srg' in rule['references']['disa']:
                new_refs['disa']['srg'] = rule['references']['disa']['srg']
            if 'controls v8' in rule['references']['cis']:
                new_refs['cis']['controls v8'] = rule['references']['cis']['controls v8']

            if 'macos' in rule.keys():
                del rule['macos']
                spec_var = "macOS"
            if 'macOS' in rule.keys():
                del rule['macOS']
                spec_var = "macOS"
            if 'ios' in rule.keys():
                del rule['ios']
                spec_var = "iOS"
            if 'iOS' in rule.keys():
                del rule['iOS']
                spec_var = "iOS"
            if 'visionOS' in rule.keys():
                del rule['visionOS']
                spec_var = "visionOS"
            
            if not rule['id'] in new_rules.keys():
                new_rules[rule['id']] = rule

            if "os_specifics" not in new_rules[rule['id']].keys():
                new_rules[rule['id']]['os_specifics'] = {}
            if spec_var not in new_rules[rule['id']]['os_specifics'].keys():
                new_rules[rule['id']]['os_specifics'][spec_var] = {}
            
           

            new_rules[rule['id']]['references'].update(new_refs)
            try:
                new_rules[rule["id"]]["os_specifics"][spec_var].update(os_specs)
            except KeyError:
                new_rules[rule['id']]['os_specifics'][spec_var] = os_specs
                
            current_tags=rule['tags']
            new_tags=new_rules[rule["id"]]["tags"]
            combined_tags=current_tags + list(set(new_tags) - set(current_tags))
            new_rules[rule["id"]]["tags"]=combined_tags
        
            # review all of the OS specific info, if there are
            # references_to_verify = ["cce", "cci", "800-53r5", "800-53r4", "srg", "disa_stig", "800-171r2", "cis", "sfr"]
            # for _r in references_to_verify:
            #     for _os, _specs in new_rules[rule['id']]['os_specifics'][spec_var].items():
            #         found_in_os = 0
            #         if _r in new_rules[rule['id']]['os_specifics'][spec_var][_os].keys():
            #             found_in_os += 1
            #             continue
                    
            #         if _r in new_rules[rule["id"]]["references"].keys(): 
            #             del new_rules[rule["id"]]["references"][_r]


    # pprint.pprint(new_rules)


    # reorder references

    for name, rule in new_rules.items():
        
        for _os, _v in rule["os_specifics"].items():
            if len(_v) == 1:
                # rule["os_specifics"][_os][list(_v.keys())[0]] = {}
                break
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
