#!/usr/bin/env python3
"""
Tool for generating baseline files for the macOS Security Compliance Project.
This script takes a keyword/tag and generates a baseline file with rules containing that tag.

This script uses the RuleParser utilities from the mscp.utils module, which handle
both parsing and validation of rules internally. Error handling is now managed
at the module level for consistency across different scripts.
"""

import os
import sys
import yaml
import argparse
from pathlib import Path
from typing import Dict, List, Optional, Any, Set

from mscp.utils import RuleParser
from mscp.utils.parser import clean_error_message
from mscp.models import Rule


def parse_args():
    """Parse command-line arguments."""
    parser = argparse.ArgumentParser(
        description="Generate a baseline file with rules containing a specific tag or belonging to a specific benchmark."
    )

    parser.add_argument(
        "-k", "--keyword",
        type=str,
        help="Keyword to filter rules - can be a tag (like '800-53r5_low') or benchmark name (like 'ios_stig')."
    )

    # List available keywords (tags and benchmarks)
    parser.add_argument(
        "-l", "--list-keywords",
        action="store_true",
        help="List all available keywords (tags and benchmarks) that can be used for filtering."
    )

    # Platform options
    parser.add_argument(
        "-p", "--platform",
        type=str,
        choices=["macOS", "iOS", "visionOS", "all"],
        default="macOS",
        help="Target platform for the baseline (default: macOS)."
    )
    parser.add_argument(
        "--list-platforms",
        action="store_true",
        help="List all available platforms and their OS versions."
    )

    # Other options
    parser.add_argument(
        "-c", "--controls",
        action="store_true",
        help="Output the 800-53 controls covered by the rules."
    )
    parser.add_argument(
        "-t", "--tailor",
        action="store_true",
        help="Customize the baseline to your organization's values."
    )
    parser.add_argument(
        "--output-dir",
        type=str,
        default=None,
        help="Directory to write the baseline file (default: ../build/baselines/<platform>)"
    )

    return parser.parse_args()


def get_available_keywords(rules: List[Rule]) -> Dict[str, Dict[str, Any]]:
    """
    Get all available keywords from the rules (both tags and benchmarks).

    Args:
        rules: List of Rule objects.

    Returns:
        Dictionary of keywords mapped to metadata, including type and platforms.
    """
    keywords: Dict[str, Dict[str, Any]] = {}

    # Add special keyword for all rules
    keywords["all_rules"] = {"type": "special", "platforms": ["all"]}

    # Get tags
    for rule in rules:
        if rule.tags:
            for tag in rule.tags:
                if tag not in keywords:
                    keywords[tag] = {"type": "tag", "platforms": ["all"]}

    # Get benchmarks with platform information
    for rule in rules:
        # Check macOS benchmarks
        if rule.platforms.macOS:
            # Check properties directly for macOS platform (varies between models)
            if hasattr(rule.platforms.macOS, "os_13_0") and rule.platforms.macOS.os_13_0 and hasattr(rule.platforms.macOS.os_13_0, "benchmarks") and rule.platforms.macOS.os_13_0.benchmarks:
                for benchmark in rule.platforms.macOS.os_13_0.benchmarks:
                    if benchmark.name not in keywords:
                        keywords[benchmark.name] = {"type": "benchmark", "platforms": ["macOS"]}
                    elif keywords[benchmark.name]["type"] == "benchmark" and "macOS" not in keywords[benchmark.name]["platforms"]:
                        keywords[benchmark.name]["platforms"].append("macOS")

            if hasattr(rule.platforms.macOS, "os_14_0") and rule.platforms.macOS.os_14_0 and hasattr(rule.platforms.macOS.os_14_0, "benchmarks") and rule.platforms.macOS.os_14_0.benchmarks:
                for benchmark in rule.platforms.macOS.os_14_0.benchmarks:
                    if benchmark.name not in keywords:
                        keywords[benchmark.name] = {"type": "benchmark", "platforms": ["macOS"]}
                    elif keywords[benchmark.name]["type"] == "benchmark" and "macOS" not in keywords[benchmark.name]["platforms"]:
                        keywords[benchmark.name]["platforms"].append("macOS")

            if hasattr(rule.platforms.macOS, "os_15_0") and rule.platforms.macOS.os_15_0 and hasattr(rule.platforms.macOS.os_15_0, "benchmarks") and rule.platforms.macOS.os_15_0.benchmarks:
                for benchmark in rule.platforms.macOS.os_15_0.benchmarks:
                    if benchmark.name not in keywords:
                        keywords[benchmark.name] = {"type": "benchmark", "platforms": ["macOS"]}
                    elif keywords[benchmark.name]["type"] == "benchmark" and "macOS" not in keywords[benchmark.name]["platforms"]:
                        keywords[benchmark.name]["platforms"].append("macOS")

        # Check iOS benchmarks
        if rule.platforms.iOS:
            if hasattr(rule.platforms.iOS, "os_16_0") and rule.platforms.iOS.os_16_0 and hasattr(rule.platforms.iOS.os_16_0, "benchmarks") and rule.platforms.iOS.os_16_0.benchmarks:
                for benchmark in rule.platforms.iOS.os_16_0.benchmarks:
                    if benchmark.name not in keywords:
                        keywords[benchmark.name] = {"type": "benchmark", "platforms": ["iOS"]}
                    elif keywords[benchmark.name]["type"] == "benchmark" and "iOS" not in keywords[benchmark.name]["platforms"]:
                        keywords[benchmark.name]["platforms"].append("iOS")

            if hasattr(rule.platforms.iOS, "os_17_0") and rule.platforms.iOS.os_17_0 and hasattr(rule.platforms.iOS.os_17_0, "benchmarks") and rule.platforms.iOS.os_17_0.benchmarks:
                for benchmark in rule.platforms.iOS.os_17_0.benchmarks:
                    if benchmark.name not in keywords:
                        keywords[benchmark.name] = {"type": "benchmark", "platforms": ["iOS"]}
                    elif keywords[benchmark.name]["type"] == "benchmark" and "iOS" not in keywords[benchmark.name]["platforms"]:
                        keywords[benchmark.name]["platforms"].append("iOS")

            if hasattr(rule.platforms.iOS, "os_18_0") and rule.platforms.iOS.os_18_0 and hasattr(rule.platforms.iOS.os_18_0, "benchmarks") and rule.platforms.iOS.os_18_0.benchmarks:
                for benchmark in rule.platforms.iOS.os_18_0.benchmarks:
                    if benchmark.name not in keywords:
                        keywords[benchmark.name] = {"type": "benchmark", "platforms": ["iOS"]}
                    elif keywords[benchmark.name]["type"] == "benchmark" and "iOS" not in keywords[benchmark.name]["platforms"]:
                        keywords[benchmark.name]["platforms"].append("iOS")

        # Check visionOS benchmarks
        if rule.platforms.visionOS:
            if hasattr(rule.platforms.visionOS, "os_2_0") and rule.platforms.visionOS.os_2_0 and hasattr(rule.platforms.visionOS.os_2_0, "benchmarks") and rule.platforms.visionOS.os_2_0.benchmarks:
                for benchmark in rule.platforms.visionOS.os_2_0.benchmarks:
                    if benchmark.name not in keywords:
                        keywords[benchmark.name] = {"type": "benchmark", "platforms": ["visionOS"]}
                    elif keywords[benchmark.name]["type"] == "benchmark" and "visionOS" not in keywords[benchmark.name]["platforms"]:
                        keywords[benchmark.name]["platforms"].append("visionOS")

    return keywords


def get_available_benchmarks(rules: List[Rule]) -> List[str]:
    """
    Get all available benchmarks from the rules.

    Args:
        rules: List of Rule objects.

    Returns:
        Sorted list of unique benchmarks.
    """
    all_benchmarks: Set[str] = set()

    for rule in rules:
        # Get benchmarks from the rule using the new method
        benchmarks = rule.get_benchmarks()
        if benchmarks:
            all_benchmarks.update(benchmarks)

    return sorted(list(all_benchmarks))


def filter_rules_by_keyword(rules: List[Rule], keyword: str, platform: str = None) -> List[Rule]:
    """
    Filter rules by a unified keyword (can be a tag or benchmark).
    The platform filter is already applied to the rules list, but we need
    to ensure that benchmarks are checked against the correct platform.

    Args:
        rules: List of Rule objects (already filtered by platform).
        keyword: Keyword to filter by (tag or benchmark name).
        platform: The target platform (macOS, iOS, visionOS, or all).

    Returns:
        List of rules matching the keyword.
    """
    if keyword == "all_rules":
        return rules

    # Check as a tag first
    tag_matches = [rule for rule in rules if rule.tags and keyword in rule.tags]

    # If no tag matches, try as a benchmark
    if not tag_matches:
        if platform == "all":
            # For "all" platform, check all benchmarks
            benchmark_matches = [rule for rule in rules if keyword in rule.get_benchmarks()]
        else:
            # For specific platform, check that the benchmark is actually defined
            # within that platform's specific definitions
            benchmark_matches = []
            for rule in rules:
                matched = False

                # For macOS platform
                if platform == "macOS" and rule.platforms.macOS:
                    # Check each version
                    if (hasattr(rule.platforms.macOS, "os_13_0") and rule.platforms.macOS.os_13_0 and
                        hasattr(rule.platforms.macOS.os_13_0, "benchmarks") and rule.platforms.macOS.os_13_0.benchmarks):
                        if any(b.name == keyword for b in rule.platforms.macOS.os_13_0.benchmarks):
                            benchmark_matches.append(rule)
                            matched = True

                    if not matched and (hasattr(rule.platforms.macOS, "os_14_0") and rule.platforms.macOS.os_14_0 and
                        hasattr(rule.platforms.macOS.os_14_0, "benchmarks") and rule.platforms.macOS.os_14_0.benchmarks):
                        if any(b.name == keyword for b in rule.platforms.macOS.os_14_0.benchmarks):
                            benchmark_matches.append(rule)
                            matched = True

                    if not matched and (hasattr(rule.platforms.macOS, "os_15_0") and rule.platforms.macOS.os_15_0 and
                        hasattr(rule.platforms.macOS.os_15_0, "benchmarks") and rule.platforms.macOS.os_15_0.benchmarks):
                        if any(b.name == keyword for b in rule.platforms.macOS.os_15_0.benchmarks):
                            benchmark_matches.append(rule)

                # For iOS platform
                elif platform == "iOS" and rule.platforms.iOS:
                    matched = False

                    if (hasattr(rule.platforms.iOS, "os_16_0") and rule.platforms.iOS.os_16_0 and
                        hasattr(rule.platforms.iOS.os_16_0, "benchmarks") and rule.platforms.iOS.os_16_0.benchmarks):
                        if any(b.name == keyword for b in rule.platforms.iOS.os_16_0.benchmarks):
                            benchmark_matches.append(rule)
                            matched = True

                    if not matched and (hasattr(rule.platforms.iOS, "os_17_0") and rule.platforms.iOS.os_17_0 and
                        hasattr(rule.platforms.iOS.os_17_0, "benchmarks") and rule.platforms.iOS.os_17_0.benchmarks):
                        if any(b.name == keyword for b in rule.platforms.iOS.os_17_0.benchmarks):
                            benchmark_matches.append(rule)
                            matched = True

                    if not matched and (hasattr(rule.platforms.iOS, "os_18_0") and rule.platforms.iOS.os_18_0 and
                        hasattr(rule.platforms.iOS.os_18_0, "benchmarks") and rule.platforms.iOS.os_18_0.benchmarks):
                        if any(b.name == keyword for b in rule.platforms.iOS.os_18_0.benchmarks):
                            benchmark_matches.append(rule)

                # For visionOS platform
                elif platform == "visionOS" and rule.platforms.visionOS:
                    if (hasattr(rule.platforms.visionOS, "os_2_0") and rule.platforms.visionOS.os_2_0 and
                        hasattr(rule.platforms.visionOS.os_2_0, "benchmarks") and rule.platforms.visionOS.os_2_0.benchmarks):
                        if any(b.name == keyword for b in rule.platforms.visionOS.os_2_0.benchmarks):
                            benchmark_matches.append(rule)

        return benchmark_matches

    return tag_matches




def get_controls(rules: List[Rule]) -> List[str]:
    """
    Get all NIST 800-53 controls covered by the rules.

    Args:
        rules: List of Rule objects.

    Returns:
        Sorted list of unique controls.
    """
    all_controls: Set[str] = set()

    for rule in rules:
        if rule.references and rule.references.nist and rule.references.nist.cfr_800_53r5:
            all_controls.update(rule.references.nist.cfr_800_53r5)

    return sorted(list(all_controls))


def filter_rules_by_platform(rules: List[Rule], platform: str) -> List[Rule]:
    """
    Filter rules by a specific platform.

    Args:
        rules: List of Rule objects.
        platform: Platform to filter by (macOS, iOS, visionOS, or all).

    Returns:
        List of rules applicable to the platform.
    """
    if platform == "all":
        return rules

    if platform == "macOS":
        return [rule for rule in rules if rule.platforms.macOS]
    elif platform == "iOS":
        return [rule for rule in rules if rule.platforms.iOS]
    elif platform == "visionOS":
        return [rule for rule in rules if rule.platforms.visionOS]

    return []


def get_platform_versions(rules: List[Rule]) -> Dict[str, List[str]]:
    """
    Get all available platforms and their OS versions.

    Args:
        rules: List of Rule objects.

    Returns:
        Dictionary of platforms and their OS versions.
    """
    platforms = {
        "macOS": set(),
        "iOS": set(),
        "visionOS": set()
    }

    for rule in rules:
        # Check macOS versions
        if rule.platforms.macOS:
            if hasattr(rule.platforms.macOS, "os_13_0") and rule.platforms.macOS.os_13_0:
                platforms["macOS"].add("13.0")
            if hasattr(rule.platforms.macOS, "os_14_0") and rule.platforms.macOS.os_14_0:
                platforms["macOS"].add("14.0")
            if hasattr(rule.platforms.macOS, "os_15_0") and rule.platforms.macOS.os_15_0:
                platforms["macOS"].add("15.0")

        # Check iOS versions
        if rule.platforms.iOS:
            if hasattr(rule.platforms.iOS, "os_16_0") and rule.platforms.iOS.os_16_0:
                platforms["iOS"].add("16.0")
            if hasattr(rule.platforms.iOS, "os_17_0") and rule.platforms.iOS.os_17_0:
                platforms["iOS"].add("17.0")
            if hasattr(rule.platforms.iOS, "os_18_0") and rule.platforms.iOS.os_18_0:
                platforms["iOS"].add("18.0")

        # Check visionOS versions
        if rule.platforms.visionOS:
            if hasattr(rule.platforms.visionOS, "os_2_0") and rule.platforms.visionOS.os_2_0:
                platforms["visionOS"].add("2.0")

    # Convert sets to sorted lists
    for platform in platforms:
        platforms[platform] = sorted(list(platforms[platform]))

    return platforms


def parse_authors(authors_data: Dict[str, Any]) -> str:
    """
    Parse authors data into a formatted string.
    
    Args:
        authors_data: Authors data from mscp-data.yaml.
        
    Returns:
        Formatted authors string.
    """
    author_block = "*macOS Security Compliance Project*\n\n  "
    
    if "preamble" in authors_data:
        preamble = authors_data["preamble"]
        author_block += f"{preamble}\n  "
    
    author_block += "|===\n  "
    for name in authors_data["names"]:
        author_block += f"|{name}\n  "
    author_block += "|===\n"
    
    return author_block


def append_authors(authors: str, name: str, org: str) -> str:
    """
    Append custom author to authors string.
    
    Args:
        authors: Existing authors string.
        name: Custom author name.
        org: Custom author organization.
        
    Returns:
        Updated authors string.
    """
    author_block = "*Security configuration tailored by:*\n  "
    author_block += "|===\n  "
    author_block += f"|{name}|{org}\n  "
    author_block += "|===\n  "
    author_block += authors
    
    return author_block


def sanitized_input(prompt, type_=None, range_=None, default_=None):
    """
    Get sanitized user input with validation.
    
    Args:
        prompt: Prompt text.
        type_: Expected input type.
        range_: Expected input range.
        default_: Default value if input is empty.
        
    Returns:
        Validated user input.
    """
    while True:
        ui = input(prompt) or default_
        if type_ is not None:
            try:
                ui = type_(ui)
            except ValueError:
                print(f"Input type must be {type_.__name__}.")
                continue
        if type_ is str:
            if ui.isnumeric():
                print(f"Input type must be {type_.__name__}.")
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


def write_odv_custom_rule(rule_id: str, odv_value: Any):
    """
    Write a custom rule with an ODV value.
    
    Args:
        rule_id: Rule ID.
        odv_value: Custom ODV value.
    """
    custom_dir = Path("../custom/rules")
    if not custom_dir.exists():
        os.makedirs(custom_dir)
    
    rule_path = custom_dir / f"{rule_id}.yaml"
    
    if rule_path.exists():
        with open(rule_path) as f:
            rule_yaml = yaml.safe_load(f) or {}
    else:
        rule_yaml = {}
    
    # Add ODV to rule_yaml
    rule_yaml["odv"] = {"custom": odv_value}
    
    with open(rule_path, "w") as f:
        yaml.dump(rule_yaml, f, explicit_start=True)


def remove_odv_custom_rule(rule_id: str):
    """
    Remove ODV from a custom rule.
    
    Args:
        rule_id: Rule ID.
    """
    rule_path = Path("../custom/rules") / f"{rule_id}.yaml"
    
    if not rule_path.exists():
        return
    
    with open(rule_path) as f:
        rule_yaml = yaml.safe_load(f) or {}
    
    if "odv" in rule_yaml:
        rule_yaml.pop("odv")
    
    if rule_yaml:
        with open(rule_path, "w") as f:
            yaml.dump(rule_yaml, f, explicit_start=True)
    else:
        os.remove(rule_path)


def odv_query(rules: List[Rule], benchmark: str) -> List[Rule]:
    """
    Query user for ODV values.
    
    Args:
        rules: List of Rule objects.
        benchmark: Benchmark name.
        
    Returns:
        List of included rules.
    """
    print("The inclusion of any given rule is a risk-based-decision (RBD). While each rule is mapped to an 800-53 control, deploying it in your organization should be part of the decision-making process.")
    print("You will be prompted to include each rule, and for those with specific organizational defined values (ODV), you will be prompted for those as well.\n")
    
    if benchmark != "recommended":
        print(f"WARNING: You are attempting to tailor an already established benchmark. Excluding rules or modifying ODVs may not meet the compliance of the established benchmark.\n")
    
    included_rules = []
    queried_rule_ids = []
    include_all = False
    
    for rule in rules:
        get_odv = False
        
        # Always include inherent rules
        if rule.tags and "inherent" in rule.tags:
            include = "Y"
        elif include_all:
            if rule.id not in queried_rule_ids:
                include = "Y"
                get_odv = True
                queried_rule_ids.append(rule.id)
                remove_odv_custom_rule(rule.id)
        else:
            if rule.id not in queried_rule_ids:
                include = sanitized_input(
                    f"Would you like to include the rule for \"{rule.id}\" in your benchmark? [Y/n/all/?]: ",
                    str.lower,
                    range_=("y", "n", "all", "?"),
                    default_="y"
                )
                
                if include == "?":
                    print(f"Rule Details: \n{rule.discussion}")
                    include = sanitized_input(
                        f"Would you like to include the rule for \"{rule.id}\" in your benchmark? [Y/n/all]: ",
                        str.lower,
                        range_=("y", "n", "all"),
                        default_="y"
                    )
                
                queried_rule_ids.append(rule.id)
                get_odv = True
                remove_odv_custom_rule(rule.id)
                
                if include.upper() == "ALL":
                    include_all = True
                    include = "y"
        
        if include.upper() == "Y":
            included_rules.append(rule)
            
            # Handle ODV if present
            if get_odv and hasattr(rule, "odv") and rule.odv is not None:
                if benchmark == "recommended" and "recommended" in rule.odv:
                    print(f"\nODV Hint: {rule.odv.get('hint', {}).get('description', '')}")
                    recommended_value = rule.odv.get("recommended")
                    
                    if isinstance(recommended_value, int):
                        odv = sanitized_input(
                            f'Enter the ODV for "{rule.id}" or press Enter for the recommended value ({recommended_value}): ',
                            int,
                            default_=recommended_value
                        )
                    elif isinstance(recommended_value, bool):
                        odv = sanitized_input(
                            f'Enter the ODV for "{rule.id}" or press Enter for the recommended value ({recommended_value}): ',
                            bool,
                            default_=recommended_value
                        )
                    else:
                        odv = sanitized_input(
                            f'Enter the ODV for "{rule.id}" or press Enter for the recommended value ({recommended_value}): ',
                            str,
                            default_=recommended_value
                        )
                    
                    if odv != recommended_value:
                        write_odv_custom_rule(rule.id, odv)
                elif benchmark in rule.odv:
                    print(f"\nODV Hint: {rule.odv.get('hint', {}).get('description', '')}")
                    benchmark_value = rule.odv.get(benchmark)
                    
                    if isinstance(benchmark_value, int):
                        odv = sanitized_input(
                            f'Enter the ODV for "{rule.id}" or press Enter for the default value ({benchmark_value}): ',
                            int,
                            default_=benchmark_value
                        )
                    elif isinstance(benchmark_value, bool):
                        odv = sanitized_input(
                            f'Enter the ODV for "{rule.id}" or press Enter for the default value ({benchmark_value}): ',
                            bool,
                            default_=benchmark_value
                        )
                    else:
                        odv = sanitized_input(
                            f'Enter the ODV for "{rule.id}" or press Enter for the default value ({benchmark_value}): ',
                            str,
                            default_=benchmark_value
                        )
                    
                    if odv != benchmark_value:
                        write_odv_custom_rule(rule.id, odv)
    
    return included_rules


def generate_baseline(rules: List[Rule], version_info: Dict[str, Any], baseline_title: str, 
                      benchmark: str, authors_text: str, full_title: str) -> str:
    """
    Generate baseline file content.
    
    Args:
        rules: List of Rule objects.
        version_info: Version information.
        baseline_title: Baseline title string.
        benchmark: Benchmark name.
        authors_text: Formatted authors text.
        full_title: Full title for the baseline.
        
    Returns:
        Baseline file content.
    """
    # Categorize rules by section
    inherent_rules = []
    permanent_rules = []
    na_rules = []
    supplemental_rules = []
    other_rules = []
    sections = set()
    
    for rule in rules:
        if rule.tags:
            if "inherent" in rule.tags:
                inherent_rules.append(rule.id)
                continue
            elif "permanent" in rule.tags:
                permanent_rules.append(rule.id)
                continue
            elif "n_a" in rule.tags:
                na_rules.append(rule.id)
                continue
            elif "supplemental" in rule.tags:
                supplemental_rules.append(rule.id)
                continue
        
        # Regular rule
        other_rules.append(rule.id)
        
        # Determine section
        if rule.id.startswith("system_settings"):
            section_name = "_".join(rule.id.split("_")[:2])
        else:
            section_name = rule.id.split("_")[0]
        
        sections.add(section_name)
    
    # Define section titles mapping
    section_titles = {
        "auth": "authentication",
        "audit": "auditing",
        "os": version_info["os"],
        "pwpolicy": "passwordpolicy",
        "icloud": "icloud",
        "sysprefs": "systempreferences",
        "system_settings": "systemsettings",
        "sys_prefs": "systempreferences",
        "srg": "srg"
    }
    
    # Build output text
    output_text = f'title: "{version_info["platform"]} {version_info["os"]}: Security Configuration -{full_title} {baseline_title}"\n'
    output_text += f'description: |\n  This guide describes the actions to take when securing a {version_info["platform"]} {version_info["os"]} system against the{full_title} {baseline_title} security baseline.\n'
    
    if benchmark == "recommended":
        output_text += "\n  Information System Security Officers and benchmark creators can use this catalog of settings in order to assist them in security benchmark creation. This list is a catalog, not a checklist or benchmark, and satisfaction of every item is not likely to be possible or sensible in many operational scenarios.\n"
    
    # Add authors
    output_text += f'authors: |\n  {authors_text}'
    
    # Add parent values
    output_text += f'parent_values: "{benchmark}"\n'
    output_text += 'profile:\n'
    
    # Sort rule lists
    other_rules.sort()
    inherent_rules.sort()
    permanent_rules.sort()
    na_rules.sort()
    supplemental_rules.sort()
    sections = sorted(list(sections))
    
    # Add regular rules by section
    if other_rules:
        for section in sections:
            section_title = section_titles.get(section, section)
            output_text += f'  - section: "{section_title}"\n'
            output_text += f'    rules:\n'
            
            section_rules = [rule for rule in other_rules if rule.startswith(section)]
            for rule in section_rules:
                output_text += f'      - {rule}\n'
    
    # Add inherent rules
    if inherent_rules:
        output_text += '  - section: "Inherent"\n'
        output_text += '    rules:\n'
        for rule in inherent_rules:
            output_text += f'      - {rule}\n'
    
    # Add permanent rules
    if permanent_rules:
        output_text += '  - section: "Permanent"\n'
        output_text += '    rules:\n'
        for rule in permanent_rules:
            output_text += f'      - {rule}\n'
    
    # Add not applicable rules
    if na_rules:
        output_text += '  - section: "not_applicable"\n'
        output_text += '    rules:\n'
        for rule in na_rules:
            output_text += f'      - {rule}\n'
    
    # Add supplemental rules
    if supplemental_rules:
        output_text += '  - section: "Supplemental"\n'
        output_text += '    rules:\n'
        for rule in supplemental_rules:
            output_text += f'      - {rule}\n'
    
    return output_text


def main():
    """Main function for generating baselines."""
    # Parse command-line arguments
    args = parse_args()
    
    # Get repository root directory
    file_dir = os.path.dirname(os.path.abspath(__file__))
    repo_root = os.path.dirname(file_dir)
    
    # Save original working directory
    original_dir = os.getcwd()
    
    # Change to script directory
    os.chdir(file_dir)
    
    # Initialize parser
    parser = RuleParser()
    
    try:
        # Parse all rules with validation
        valid_results = [r for r in parser.parse_rules_with_validation() if r["valid"]]
        all_rules = [r["rule"] for r in valid_results]

        # Check for any validation errors
        invalid_results = [r for r in parser.parse_rules_with_validation(only_invalid=True)]
        if invalid_results:
            print(f"Warning: {len(invalid_results)} rules have validation errors and will be excluded:")
            for result in invalid_results[:5]:  # Show first 5 only to keep output concise
                print(f"  {result['id']}: {result['errors'][0]}")
            if len(invalid_results) > 5:
                print(f"  ... and {len(invalid_results) - 5} more rules")
            print()

        # Handle list keywords option
        if args.list_keywords:
            keywords = get_available_keywords(all_rules)

            print("Available keywords (tags and benchmarks):")

            print("\nTags (applicable to all platforms):")
            for keyword, info in sorted(keywords.items()):
                if info["type"] == "tag":
                    print(f"  {keyword}")

            print("\nBenchmarks (platform-specific):")
            for keyword, info in sorted(keywords.items()):
                if info["type"] == "benchmark":
                    platforms_str = ", ".join(info["platforms"])
                    print(f"  {keyword} (Platforms: {platforms_str})")

            print("\nSpecial keywords:")
            for keyword, info in sorted(keywords.items()):
                if info["type"] == "special":
                    print(f"  {keyword}")

            return 0

        if args.list_platforms:
            platforms = get_platform_versions(all_rules)
            print("Available platforms and versions:")
            for platform, versions in platforms.items():
                if versions:
                    print(f"  {platform}: {', '.join(versions)}")
            return 0

        # Check if keyword is provided
        if not args.keyword:
            print("Error: No keyword provided. Use --keyword to specify a filtering keyword or --list-keywords to see available options.")
            return 1

        # Apply platform filter first
        platform_filtered_rules = filter_rules_by_platform(all_rules, args.platform)

        # Then filter by the unified keyword, passing the platform for benchmark-specific filtering
        keyword = args.keyword
        filtered_rules = filter_rules_by_keyword(platform_filtered_rules, keyword, args.platform)
        filter_name = keyword  # For output naming
        
        if not filtered_rules:
            platform_msg = f" for platform '{args.platform}'" if args.platform != "all" else ""
            print(f"No rules found for keyword '{filter_name}'{platform_msg}. Use --list-keywords to see available options.")
            return 1
        
        # Handle controls option
        if args.controls:
            baselines_file = os.path.join(repo_root, "includes", "800-53_baselines.yaml")
            with open(baselines_file) as f:
                baselines = yaml.safe_load(f)
            
            controls = get_controls(filtered_rules)
            needed_controls = baselines.get("low", [])
            
            missing_controls = [c for c in needed_controls if c not in controls]
            if missing_controls:
                print(f"Missing controls ({len(missing_controls)}):")
                for control in missing_controls:
                    print(f"  {control} - missing from any rule, needs a rule, or included in supplemental")
            else:
                print("All required controls are covered by the rules.")
            
            return 0
        
        # Load version information
        version_file = os.path.join(repo_root, "VERSION.yaml")
        with open(version_file) as f:
            version_info = yaml.safe_load(f)
        
        # Load MSCP data
        mscp_data_file = os.path.join(repo_root, "includes", "mscp-data.yaml")
        with open(mscp_data_file) as f:
            mscp_data = yaml.safe_load(f)
        
        # Determine benchmark type
        established_benchmarks = ["stig", "cis_lvl1", "cis_lvl2"]
        if any(bm in filter_name for bm in established_benchmarks):
            benchmark = filter_name
        else:
            benchmark = "recommended"

        # Get authors
        if filter_name in mscp_data.get("authors", {}):
            authors_text = parse_authors(mscp_data["authors"][filter_name])
        else:
            authors_text = "|===\n  |Name|Organization\n  |===\n"

        # Get title
        if filter_name in mscp_data.get("titles", {}) and not args.tailor:
            full_title = f" {mscp_data['titles'][filter_name]}"
        elif args.tailor:
            full_title = ""
        else:
            full_title = f" {filter_name}"
        
        # Create output directory based on platform
        if args.output_dir:
            build_path = Path(args.output_dir)
        else:
            # Create platform-specific output directory
            if args.platform == "all":
                build_path = Path(repo_root) / "build" / "baselines" / "all_platforms"
            else:
                build_path = Path(repo_root) / "build" / "baselines" / args.platform.lower()

        if not build_path.exists():
            os.makedirs(build_path, exist_ok=True)
        
        # Handle tailoring
        baseline_title = ""
        output_rules = filtered_rules
        
        if args.tailor:
            # Prompt for tailored benchmark details
            tailored_filename = sanitized_input(
                f'Enter a name for your tailored benchmark or press Enter for the default value ({filter_name}): ',
                str,
                default_=filter_name
            )

            custom_author_name = sanitized_input('Enter your name: ')
            custom_author_org = sanitized_input('Enter your organization: ')
            authors_text = append_authors(authors_text, custom_author_name, custom_author_org)

            if tailored_filename == filter_name:
                baseline_title = f"{filter_name.upper()} (Tailored)"
            else:
                baseline_title = f"{tailored_filename.upper()} (Tailored from {filter_name.upper()})"
            
            # Run ODV query
            output_rules = odv_query(filtered_rules, benchmark)
            
            # Generate baseline file
            baseline_content = generate_baseline(
                output_rules,
                version_info,
                baseline_title,
                benchmark,
                authors_text,
                full_title
            )
            
            # Add platform to filename for clarity
            if args.platform != "all" and not tailored_filename.lower().startswith(args.platform.lower()):
                output_file = build_path / f"{args.platform.lower()}_{tailored_filename}.yaml"
            else:
                output_file = build_path / f"{tailored_filename}.yaml"
        else:
            # Generate baseline file without tailoring
            baseline_content = generate_baseline(
                output_rules,
                version_info,
                baseline_title,
                benchmark,
                authors_text,
                full_title
            )
            
            # Add platform to filename for clarity
            if args.platform != "all" and not filter_name.lower().startswith(args.platform.lower()):
                output_file = build_path / f"{args.platform.lower()}_{filter_name}.yaml"
            else:
                output_file = build_path / f"{filter_name}.yaml"
        
        # Write baseline file
        with open(output_file, "w") as f:
            f.write(baseline_content)
        
        print(f"Baseline file created: {output_file}")
        return 0
    
    except Exception as e:
        # Clean and format the error message
        cleaned_error = clean_error_message(str(e))
        print(f"Error: {cleaned_error}")

        # Show detailed traceback only in debug mode
        if os.environ.get("MSCP_DEBUG"):
            import traceback
            traceback.print_exc()

        return 1
    
    finally:
        # Restore original working directory
        os.chdir(original_dir)


if __name__ == "__main__":
    sys.exit(main())