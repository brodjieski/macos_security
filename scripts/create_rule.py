#!/usr/bin/env python3
"""
Script to create a new rule template file for the macOS Security Compliance Project.
This script prompts for a rule ID and generates a YAML template with all required fields.
"""

import os
import sys
import yaml
from pathlib import Path
import argparse
import re


def parse_args():
    """Parse command-line arguments."""
    parser = argparse.ArgumentParser(description="Create a new MSCP rule template")
    parser.add_argument(
        "--category", 
        type=str,
        choices=["os", "audit", "auth", "pwpolicy", "system_settings", "icloud", "settings"],
        help="Category for the new rule (default: will prompt)"
    )
    parser.add_argument(
        "--rule-id", 
        type=str, 
        help="ID for the new rule (default: will prompt)"
    )
    parser.add_argument(
        "--title", 
        type=str, 
        help="Title for the new rule (default: will prompt)"
    )
    parser.add_argument(
        "--force", 
        action="store_true", 
        help="Overwrite existing rule if it exists"
    )
    
    return parser.parse_args()


def prompt_with_validation(prompt_text, validation_func=None, error_message=None):
    """
    Prompt user for input with optional validation.
    
    Args:
        prompt_text: The prompt text to display.
        validation_func: Optional function that validates input and returns bool.
        error_message: Optional error message to display if validation fails.
        
    Returns:
        Validated user input.
    """
    while True:
        user_input = input(prompt_text)
        
        if validation_func is None or validation_func(user_input):
            return user_input
        
        print(error_message or "Invalid input. Please try again.")


def validate_rule_id(rule_id):
    """
    Validate rule ID format.
    
    Args:
        rule_id: The rule ID to validate.
        
    Returns:
        True if valid, False otherwise.
    """
    # Rule ID should be in snake_case format
    pattern = r'^[a-z][a-z0-9_]+[a-z0-9]$'
    return bool(re.match(pattern, rule_id))


def validate_category(category):
    """
    Validate rule category.
    
    Args:
        category: The category to validate.
        
    Returns:
        True if valid, False otherwise.
    """
    valid_categories = ["os", "audit", "auth", "pwpolicy", "system_settings", "icloud", "settings"]
    return category in valid_categories


def ensure_category_prefix(rule_id, category):
    """
    Ensure the rule ID has the category prefix.
    
    Args:
        rule_id: The rule ID to check.
        category: The category to prefix if needed.
        
    Returns:
        Rule ID with category prefix.
    """
    if not rule_id.startswith(f"{category}_"):
        return f"{category}_{rule_id}"
    return rule_id


def create_rule_template(rule_id, title, category):
    """
    Create a rule template with all required fields.
    
    Args:
        rule_id: ID for the new rule.
        title: Title for the new rule.
        category: Category for the new rule.
        
    Returns:
        Tuple of (template dictionary, comments dictionary).
    """
    template = {
        "id": rule_id,
        "title": title,
        "discussion": "",  # Empty string with comment below
        "references": {
            "nist": {
                "cce": {
                    # Empty dictionary with comment below
                },
                "800-53r5": []  # Empty list with comment below
            },
            "disa": {
                "srg": [],  # Empty list with comment below
                "cci": []   # Empty list with comment below
            },
            "cis": {
                "benchmark": {}  # Empty dictionary with comment below
            }
        },
        "platforms": {
            "macOS": {
                "introduced": "",  # Empty string with comment below
                "enforcement_info": {
                    "check": {
                        "shell": "",  # Empty string with comment below
                        "result": {
                            "string": ""  # Empty string with comment below
                        }
                    },
                    "fix": {
                        "shell": ""  # Empty string with comment below
                    }
                }
            }
        },
        "tags": []  # Empty list with comment below
    }
    
    # Add comments to the YAML (these will be added manually after YAML generation)
    comments = {
        "discussion": "# Detailed explanation of the security requirement and its importance",
        "references.nist.cce": "# Dictionary of CCE IDs with platforms as values",
        "references.nist.800-53r5": "# List of NIST 800-53r5 control IDs",
        "references.disa.srg": "# List of SRG IDs",
        "references.disa.cci": "# List of CCI IDs",
        "references.cis.benchmark": "# Dictionary of CIS benchmark versions with section numbers as values",
        "platforms.macOS.introduced": "# Minimum macOS version (e.g., '13.0')",
        "platforms.macOS.enforcement_info.check.shell": "# Shell command to check compliance (e.g., 'defaults read /path/to/plist Key')",
        "platforms.macOS.enforcement_info.check.result.string": "# Expected output string from check command (use string, integer, or boolean as appropriate)",
        "platforms.macOS.enforcement_info.fix.shell": "# Shell command to fix configuration (e.g., 'defaults write /path/to/plist Key -bool true')",
        "tags": "# List of relevant tags for categorization and searching"
    }
    
    # Optionally add mobileconfig_info for profile managed rules
    if category in ["system_settings", "settings"]:
        template["mobileconfig_info"] = [{
            "PayloadType": "",  # Empty string with comment below
            "PayloadContent": []  # Empty list with comment below
        }]
        comments["mobileconfig_info[0].PayloadType"] = "# Profile payload type (e.g., 'com.apple.screensaver')"
        comments["mobileconfig_info[0].PayloadContent"] = "# List of configuration dictionaries"
    
    return (template, comments)


def add_comments_to_yaml(yaml_text, comments):
    """
    Add comments to YAML text.

    Args:
        yaml_text: The YAML text to add comments to.
        comments: Dictionary mapping field paths to comments.

    Returns:
        YAML text with comments added.
    """
    yaml_lines = yaml_text.split('\n')
    result_lines = []

    for i, line in enumerate(yaml_lines):
        # Skip empty lines
        if not line.strip():
            result_lines.append(line)
            continue

        modified_line = line

        # Add comments to the same line
        for field, comment in comments.items():
            parts = field.split('.')

            # Handle simple fields
            if len(parts) == 1 and line.startswith(f"{parts[0]}:"):
                # Skip if discussion has content
                if parts[0] == "discussion" and not line.strip().endswith(":"):
                    continue

                # Add inline comment after the value
                modified_line = f"{line}  {comment}"
                break

            # Handle nested fields
            elif len(parts) > 1:
                # Check for array notation like mobileconfig_info[0].PayloadType
                field_prefix = parts[0]
                if '[' in field_prefix:
                    field_prefix = field_prefix.split('[')[0]

                # Find the line with this field
                if line.strip().startswith(parts[-1] + ":"):
                    # Calculate the indentation level
                    spaces = len(line) - len(line.lstrip())

                    # Find parent context
                    context_match = True
                    for j in range(i-1, -1, -1):
                        context_line = yaml_lines[j]
                        if len(context_line) - len(context_line.lstrip()) < spaces:
                            parent_field = context_line.strip().split(':')[0]
                            if parent_field != parts[-2]:
                                context_match = False
                            break

                    if context_match:
                        # Add inline comment after the value
                        modified_line = f"{line}  {comment}"
                        break

        result_lines.append(modified_line)

    return '\n'.join(result_lines)


def main():
    """Main function to create a new rule template."""
    args = parse_args()
    
    # Get the repository root directory
    repo_root = Path(__file__).parent.parent
    
    # Prompt for category if not provided
    if args.category:
        category = args.category
    else:
        category = prompt_with_validation(
            "Enter rule category (os, audit, auth, pwpolicy, system_settings, icloud, settings): ",
            validate_category,
            "Invalid category. Please enter one of: os, audit, auth, pwpolicy, system_settings, icloud, settings."
        )
    
    # Prompt for rule ID if not provided
    if args.rule_id:
        rule_id = args.rule_id
    else:
        rule_id = prompt_with_validation(
            f"Enter rule ID (snake_case format, e.g. something_secure): ",
            validate_rule_id,
            "Invalid rule ID. Use snake_case format (lowercase with underscores)."
        )
    
    # Ensure rule ID has category prefix
    rule_id = ensure_category_prefix(rule_id, category)
    
    # Prompt for title if not provided
    if args.title:
        title = args.title
    else:
        title = prompt_with_validation(
            "Enter rule title (descriptive title for the rule): "
        )
    
    # Check if rule already exists
    rule_path = repo_root / "rules" / category / f"{rule_id}.yaml"
    
    if rule_path.exists() and not args.force:
        print(f"Error: Rule already exists at {rule_path}")
        print("Use --force to overwrite the existing rule.")
        return 1
    
    # Create the rule directory if it doesn't exist
    rule_dir = rule_path.parent
    if not rule_dir.exists():
        print(f"Creating directory: {rule_dir}")
        rule_dir.mkdir(parents=True, exist_ok=True)
    
    # Create rule template
    rule_template, comments = create_rule_template(rule_id, title, category)
    
    # Save the rule template
    with open(rule_path, 'w') as f:
        # Use safe_dump for better readability
        yaml_text = yaml.safe_dump(rule_template, default_flow_style=False, sort_keys=False)
        
        # Add comments to the YAML
        commented_yaml = add_comments_to_yaml(yaml_text, comments)
        
        f.write(commented_yaml)
    
    print(f"Rule template created successfully: {rule_path}")
    print("Please edit the template to fill in the required information.")
    
    return 0


if __name__ == "__main__":
    sys.exit(main())