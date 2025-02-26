#!/usr/bin/env python3
# filename: generate_baseline.py
# description: Process a given keyword, and output a baseline file

import os.path
import glob
import os
import yaml
import argparse
import sys

# Add the util directory to the path to import our utilities
sys.path.append(os.path.join(os.path.dirname(__file__), 'util'))
from mscp_utils import (
    MacSecurityRule, get_rule_yaml, collect_rules, 
    get_controls, section_title, available_tags as get_available_tags,
    load_yaml_file
)


def create_args():
    """Configure the arguments used in the script, returns the parsed arguments
    """
    parser = argparse.ArgumentParser(
        description='Given a keyword tag, generate a generic baseline.yaml file containing rules with the tag.')
    parser.add_argument("-c", "--controls", default=None,
                        help="Output the 800-53 controls covered by the rules.", action="store_true")
    parser.add_argument("-k", "--keyword", default=None,
                        help="Keyword tag to collect rules containing the tag.", action="store")
    parser.add_argument("-l", "--list_tags", default=None,
                        help="List the available keyword tags to search for.", action="store_true")
    parser.add_argument("-t", "--tailor", default=None,
                        help="Customize the baseline to your organizations values.", action="store_true")

    return parser.parse_args()

def append_authors(authors, name, org):
    author_block = "*Security configuration tailored by:*\n  "
    author_block += "|===\n  "
    author_block += f"|{name}|{org}\n  "
    author_block += "|===\n  "
    author_block += authors
    return author_block

def parse_authors(authors_from_yaml):
    author_block = "*macOS Security Compliance Project*\n\n  "
    #  |\n  |===\n  |Name|Organization\n  |===\n
    if "preamble" in authors_from_yaml.keys():
        preamble = authors_from_yaml['preamble']
        author_block += f'{preamble}\n  '

    author_block += "|===\n  "
    for name in authors_from_yaml['names']:
        author_block += f'|{name}\n  '
    author_block += "|===\n"
    return author_block

def print_available_tags(all_rules):
    """Print all available tags from the rules
    
    Args:
        all_rules: List of MacSecurityRule objects
    """
    tags = get_available_tags(all_rules)
    for tag in tags:
        print(tag)
    return

def output_baseline(rules, version, baseline_tailored_string, benchmark, authors, full_title):
    inherent_rules = []
    permanent_rules = []
    na_rules = []
    supplemental_rules = []
    other_rules = []
    sections = []
    output_text = ""

    for rule in rules:
        if "inherent" in rule.rule_tags:
            inherent_rules.append(rule.rule_id)
        elif "permanent" in rule.rule_tags:
            permanent_rules.append(rule.rule_id)
        elif "n_a" in rule.rule_tags:
            na_rules.append(rule.rule_id)
        elif "supplemental" in rule.rule_tags:
            supplemental_rules.append(rule.rule_id)
        else:
            if rule.rule_id not in other_rules:
                other_rules.append(rule.rule_id)
            if rule.rule_id.startswith("system_settings"):
                 section_name = rule.rule_id.split("_")[0]+"_"+rule.rule_id.split("_")[1]
            else:
                 section_name = rule.rule_id.split("_")[0]
            if section_name not in sections:
                sections.append(section_name)
    if baseline_tailored_string:
        output_text = f'title: "{version["platform"]} {version["os"]}: Security Configuration -{full_title} {baseline_tailored_string}"\n'
        output_text += f'description: |\n  This guide describes the actions to take when securing a {version["platform"]} {version["os"]} system against the{full_title} {baseline_tailored_string} security baseline.\n'
    else:
        output_text = f'title: "{version["platform"]} {version["os"]}: Security Configuration -{full_title}"\n'
        output_text += f'description: |\n  This guide describes the actions to take when securing a {version["platform"]} {version["os"]} system against the{full_title} security baseline.\n'

    if benchmark == "recommended":
        output_text += "\n  Information System Security Officers and benchmark creators can use this catalog of settings in order to assist them in security benchmark creation. This list is a catalog, not a checklist or benchmark, and satisfaction of every item is not likely to be possible or sensible in many operational scenarios.\n"

    # # process authors
    output_text += f'authors: |\n  {authors}'

    output_text += f'parent_values: "{benchmark}"\n'
    output_text += 'profile:\n'

    # sort the rules
    other_rules.sort()
    inherent_rules.sort()
    permanent_rules.sort()
    na_rules.sort()
    supplemental_rules.sort()

    if len(other_rules) > 0:
        for section in sections:
            output_text += ('  - section: "{}"\n'.format(section_title(section, version["cpe"])))
            output_text += ("    rules:\n")
            for rule in other_rules:
                if rule.startswith(section):
                    output_text += ("      - {}\n".format(rule))

    if len(inherent_rules) > 0:
        output_text += ('  - section: "Inherent"\n')
        output_text += ("    rules:\n")
        for rule in inherent_rules:
            output_text += ("      - {}\n".format(rule))

    if len(permanent_rules) > 0:
        output_text += ('  - section: "Permanent"\n')
        output_text += ("    rules:\n")
        for rule in permanent_rules:
            output_text += ("      - {}\n".format(rule))

    if len(na_rules) > 0:
        output_text += ('  - section: "not_applicable"\n')
        output_text += ("    rules: \n")
        for rule in na_rules:
            output_text += ("      - {}\n".format(rule))

    if len(supplemental_rules) > 0:
        output_text += ('  - section: "Supplemental"\n')
        output_text += ("    rules:\n")
        for rule in supplemental_rules:
            output_text += ("      - {}\n".format(rule))

    return output_text

def write_odv_custom_rule(rule, odv):
    print(f"Writing custom rule for {rule.rule_id} to include value {odv}")

    if not os.path.exists("../custom/rules"):
        os.makedirs("../custom/rules")
    if os.path.exists(f"../custom/rules/{rule.rule_id}.yaml"):
        with open(f"../custom/rules/{rule.rule_id}.yaml") as f:
            rule_yaml = yaml.load(f, Loader=yaml.SafeLoader)
    else:
        rule_yaml = {}

    # add odv to rule_yaml
    rule_yaml['odv'] = {"custom" : odv}
    with open(f"../custom/rules/{rule.rule_id}.yaml", 'w') as f:
      yaml.dump(rule_yaml, f, explicit_start=True)

    return

def remove_odv_custom_rule(rule):
    odv_yaml = {}
    try:
        with open(f"../custom/rules/{rule.rule_id}.yaml") as f:
            odv_yaml = yaml.load(f, Loader=yaml.SafeLoader)
            odv_yaml.pop('odv', None)
    except:
        pass

    if odv_yaml:
        with open(f"../custom/rules/{rule.rule_id}.yaml", 'w') as f:
            yaml.dump(odv_yaml, f, explicit_start=True)
    else:
        if os.path.exists(f"../custom/rules/{rule.rule_id}.yaml"):
            os.remove(f"../custom/rules/{rule.rule_id}.yaml")

def sanitised_input(prompt, type_=None, range_=None, default_=None):
    while True:
        ui = input(prompt) or default_
        if type_ is not None:
            try:
                ui = type_(ui)
            except ValueError:
                print("Input type must be {0}.".format(type_.__name__))
                continue
        if type_ is str:
            if ui.isnumeric():
                print("Input type must be {0}.".format(type_.__name__))
                continue

        if range_ is not None and ui not in range_:
            if isinstance(range_, range):
                template = "Input must be between {0.start} and {0.stop}."
                print(template.format(range_))
            else:
                template = "Input must be {0}."
                if len(range_) == 1:
                    print(template.format(*range_))
                else:
                    expected = " or ".join((
                        ", ".join(str(x) for x in range_[:-1]),
                        str(range_[-1])
                    ))
                    print(template.format(expected))
        else:
            return ui

def odv_query(rules, benchmark):
    print("The inclusion of any given rule is a risk-based-decision (RBD).  While each rule is mapped to an 800-53 control, deploying it in your organization should be part of the decision-making process. \nYou will be prompted to include each rule, and for those with specific organizational defined values (ODV), you will be prompted for those as well.\n")

    if not benchmark == "recommended":
        print(f"WARNING: You are attempting to tailor an already established benchmark.  Excluding rules or modifying ODVs may not meet the compliance of the established benchmark.\n")

    included_rules = []
    queried_rule_ids = []

    include_all = False

    for rule in rules:
        get_odv = False

        _always_include = ['inherent']
        if any(tag in rule.rule_tags for tag in _always_include):
            #print(f"Including rule {rule.rule_id} by default")
            include = "Y"
        elif include_all:
            if rule.rule_id not in queried_rule_ids:
                include = "Y"
                get_odv = True
                queried_rule_ids.append(rule.rule_id)
                remove_odv_custom_rule(rule)
        else:
            if rule.rule_id not in queried_rule_ids:
                include = sanitised_input(f"Would you like to include the rule for \"{rule.rule_id}\" in your benchmark? [Y/n/all/?]: ", str.lower, range_=('y', 'n', 'all', '?'), default_="y")
                if include == "?":
                    print(f'Rule Details: \n{rule.rule_discussion}')
                    include = sanitised_input(f"Would you like to include the rule for \"{rule.rule_id}\" in your benchmark? [Y/n/all]: ", str.lower, range_=('y', 'n', 'all'), default_="y")
                queried_rule_ids.append(rule.rule_id)
                get_odv = True
                # remove custom ODVs if there, they will be re-written if needed
                remove_odv_custom_rule(rule)
                if include.upper() == "ALL":
                    include_all = True
                    include = "y"
        if include.upper() == "Y":
            included_rules.append(rule)
            if rule.rule_odv == "missing":
                continue
            elif get_odv:
                if benchmark == "recommended":
                    print(f'{rule.rule_odv["hint"]}')
                    if isinstance(rule.rule_odv["recommended"], int):
                         odv = sanitised_input(f'Enter the ODV for \"{rule.rule_id}\" or press Enter for the recommended value ({rule.rule_odv["recommended"]}): ', int, default_=rule.rule_odv["recommended"])
                    elif isinstance(rule.rule_odv["recommended"], bool):
                         odv = sanitised_input(f'Enter the ODV for \"{rule.rule_id}\" or press Enter for the recommended value ({rule.rule_odv["recommended"]}): ', bool, default_=rule.rule_odv["recommended"])
                    else:
                         odv = sanitised_input(f'Enter the ODV for \"{rule.rule_id}\" or press Enter for the recommended value ({rule.rule_odv["recommended"]}): ', str, default_=rule.rule_odv["recommended"])
                    if odv and odv != rule.rule_odv["recommended"]:
                        write_odv_custom_rule(rule, odv)
                else:
                    print(f'\nODV value: {rule.rule_odv["hint"]}')
                    if isinstance(rule.rule_odv[benchmark], int):
                         odv = sanitised_input(f'Enter the ODV for \"{rule.rule_id}\" or press Enter for the default value ({rule.rule_odv[benchmark]}): ', int, default_=rule.rule_odv[benchmark])
                    elif isinstance(rule.rule_odv[benchmark], bool):
                         odv = sanitised_input(f'Enter the ODV for \"{rule.rule_id}\" or press Enter for the default value ({rule.rule_odv[benchmark]}): ', bool, default_=rule.rule_odv[benchmark])
                    else:
                         odv = sanitised_input(f'Enter the ODV for \"{rule.rule_id}\" or press Enter for the default value ({rule.rule_odv[benchmark]}): ', str, default_=rule.rule_odv[benchmark])
                    if odv and odv != rule.rule_odv[benchmark]:
                        write_odv_custom_rule(rule, odv)
    return included_rules

def main():
    """Main entry point for the script"""
    args = create_args()
    
    file_dir = os.path.dirname(os.path.abspath(__file__))
    parent_dir = os.path.dirname(file_dir)

    # stash current working directory
    original_working_directory = os.getcwd()

    # switch to the scripts directory
    os.chdir(file_dir)

    all_rules = collect_rules()

    if args.list_tags:
        print_available_tags(all_rules)
        return

    if args.controls:
        baselines_file = os.path.join(parent_dir, 'includes', '800-53_baselines.yaml')
        baselines = load_yaml_file(baselines_file)

        included_controls = get_controls(all_rules)
        needed_controls = []

        for control in baselines['low']:
            if control not in needed_controls:
                needed_controls.append(control)

        for n_control in needed_controls:
            if n_control not in included_controls:
                print(f'{n_control} missing from any rule, needs a rule, or included in supplemental')

        return

    # Create build directory if it doesn't exist
    build_path = os.path.join(parent_dir, 'build', 'baselines')
    if not (os.path.isdir(build_path)):
        try:
            os.makedirs(build_path)
        except OSError:
            print(f"Creation of the directory {build_path} failed")

    # Load configuration data
    mscp_data_file = os.path.join(parent_dir, 'includes', 'mscp-data.yaml')
    mscp_data_yaml = load_yaml_file(mscp_data_file)

    version_file = os.path.join(parent_dir, "VERSION.yaml")
    version_yaml = load_yaml_file(version_file)

    # Find rules based on keyword
    found_rules = []
    for rule in all_rules:
        if args.keyword in rule.rule_tags or args.keyword == "all_rules":
            found_rules.append(rule)

    if args.keyword is None:
        print("No rules found for the keyword provided, please verify from the following list:")
        print_available_tags(all_rules)
    else:
        # Determine benchmark type
        _established_benchmarks = ['stig', 'cis_lvl1', 'cis_lvl2']
        if any(bm in args.keyword for bm in _established_benchmarks):
            benchmark = args.keyword
        else:
            benchmark = "recommended"

        # Set authors
        if args.keyword in mscp_data_yaml['authors']:
            authors = parse_authors(mscp_data_yaml['authors'][args.keyword])
        else:
            authors = "|===\n  |Name|Organization\n  |===\n"

        # Set title
        if args.keyword in mscp_data_yaml['titles'] and not args.tailor:
            full_title = f" {mscp_data_yaml['titles'][args.keyword]}"
        elif args.tailor:
            full_title = ""
        else:
            full_title = f" {args.keyword}"

        baseline_tailored_string = ""
        if args.tailor:
            # Tailor the baseline
            tailored_filename = sanitised_input(
                f'Enter a name for your tailored benchmark or press Enter for the default value ({args.keyword}): ', 
                str, 
                default_=args.keyword
            )
            custom_author_name = sanitised_input('Enter your name: ')
            custom_author_org = sanitised_input('Enter your organization: ')
            authors = append_authors(authors, custom_author_name, custom_author_org)
            
            if tailored_filename == args.keyword:
                baseline_tailored_string = f"{args.keyword.upper()} (Tailored)"
            else:
                baseline_tailored_string = f"{tailored_filename.upper()} (Tailored from {args.keyword.upper()})"
            
            # Prompt for inclusion, add ODV
            odv_baseline_rules = odv_query(found_rules, benchmark)
            
            # Write the baseline file
            output_file_path = f"{build_path}/{tailored_filename}.yaml"
            with open(output_file_path, 'w') as baseline_output_file:
                baseline_output_file.write(output_baseline(
                    odv_baseline_rules, 
                    version_yaml, 
                    baseline_tailored_string, 
                    benchmark, 
                    authors, 
                    full_title
                ))
        else:
            # Write the standard baseline file
            output_file_path = f"{build_path}/{args.keyword}.yaml"
            with open(output_file_path, 'w') as baseline_output_file:
                baseline_output_file.write(output_baseline(
                    found_rules, 
                    version_yaml, 
                    baseline_tailored_string, 
                    benchmark, 
                    authors, 
                    full_title
                ))

    # Revert back to the original directory
    os.chdir(original_working_directory)

if __name__ == "__main__":
    main()