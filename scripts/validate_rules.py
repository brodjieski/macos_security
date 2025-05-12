#!/usr/bin/env python3
"""
Tool for validating macOS Security Compliance Project rules.
This script parses and validates rule files against the schema, reporting any errors.

This script uses the RuleParser utilities from the mscp.utils module, which handle
both parsing and validation of rules internally. Error handling is now managed
at the module level for consistency across different scripts.
"""

import argparse
import sys
from pathlib import Path
from typing import Optional, List, Dict, Any

from mscp.utils import RuleParser
from mscp.models import Rule


def parse_args():
    """Parse command-line arguments."""
    parser = argparse.ArgumentParser(description="Validate MSCP rules against the schema")
    parser.add_argument(
        "--rules-dir",
        type=str,
        help="Directory containing rule files (default: ../rules/)"
    )
    # Schema validation is now handled internally by the parser module
    parser.add_argument(
        "--category",
        type=str,
        help="Filter rules by category (e.g., 'audit', 'os', etc.)"
    )
    parser.add_argument(
        "--rule-id",
        type=str,
        help="Parse and validate a specific rule by its ID"
    )
    parser.add_argument(
        "--output",
        type=str,
        choices=["text", "json"],
        default="text",
        help="Output format (default: text)"
    )
    parser.add_argument(
        "--only-invalid",
        action="store_true",
        help="Show only invalid rules"
    )
    parser.add_argument(
        "--verbose",
        "-v",
        action="store_true",
        help="Enable verbose output"
    )

    return parser.parse_args()


def add_verbose_info(result: Dict[str, Any], verbose: bool = False) -> Dict[str, Any]:
    """
    Add verbose information to a rule result.

    Args:
        result: The rule result dictionary.
        verbose: Whether to include verbose output.

    Returns:
        Updated rule result dictionary.
    """
    if verbose and result.get("valid") and "rule" in result:
        rule = result["rule"]

        # Extract platform information
        platforms = []
        if rule.platforms.macOS:
            platforms.append("macOS")
        if rule.platforms.iOS:
            platforms.append("iOS")
        if rule.platforms.visionOS:
            platforms.append("visionOS")

        result["platforms"] = platforms
        result["tags"] = rule.tags

    # Remove rule object to make the result JSON serializable
    if "rule" in result:
        del result["rule"]

    return result


def main():
    """Main function to parse and validate rules."""
    args = parse_args()

    try:
        # Initialize parser with the specified rules directory
        # Schema validation is handled internally by the parser module
        parser = RuleParser(args.rules_dir)

        results = []

        # Process rules based on command-line arguments
        if args.rule_id:
            # Process a single rule by ID
            result = parser.get_rule_by_id_with_validation(args.rule_id)
            # Add verbose information if requested
            result = add_verbose_info(result, args.verbose)
            results.append(result)

            # If rule was not found, exit early
            if not result["valid"] and "not found" in result["errors"][0]:
                print(f"Rule not found: {args.rule_id}", file=sys.stderr)
                return 1
        else:
            # Process all rules with validation
            for result in parser.parse_rules_with_validation(args.category, args.only_invalid):
                # Add verbose information if requested
                result = add_verbose_info(result, args.verbose)
                results.append(result)

        # Calculate statistics
        total_rules = len(results)
        valid_count = sum(1 for r in results if r["valid"])
        invalid_count = total_rules - valid_count
        
        # Output results
        if args.output == "json":
            import json
            output = {
                "summary": {
                    "total_rules": total_rules,
                    "valid_rules": valid_count,
                    "invalid_rules": invalid_count
                },
                "valid_rules": [r for r in results if r["valid"]],
                "invalid_rules": [r for r in results if not r["valid"]]
            }
            print(json.dumps(output, indent=2))
        else:
            # Text output
            print(f"Processed {total_rules} rules")
            print(f"Valid: {valid_count}")
            print(f"Invalid: {invalid_count}")

            # Display verbose information about valid rules if requested
            if args.verbose and valid_count > 0:
                print("\nValid rules:")
                for result in results:
                    if result["valid"]:
                        print(f"  {result['id']}: {result['title']}")
                        if "platforms" in result:
                            print(f"    Platforms: {', '.join(result['platforms'])}")
                        if "tags" in result:
                            print(f"    Tags: {', '.join(result['tags'])}")
                        print()

            # Display invalid rules with errors
            if invalid_count > 0:
                print("\nInvalid rules:")
                for result in results:
                    if not result["valid"]:
                        print(f"  {result['id']}: {result['title']}")
                        for error in result["errors"]:
                            print(f"    - {error}")
                        print()
        
        # Return non-zero exit code if there are invalid rules
        return 0 if invalid_count == 0 else 1
    
    except Exception as e:
        print(f"Error: {e}", file=sys.stderr)
        if args.verbose:
            import traceback
            traceback.print_exc()
        return 1


if __name__ == "__main__":
    sys.exit(main())