import os
import re
import yaml
from pathlib import Path
from typing import Dict, List, Optional, Union, Any, Iterator, Tuple

from ..models import Rule


def clean_error_message(error_message: str) -> str:
    """
    Clean and simplify error messages to show only the most relevant information.

    Args:
        error_message: The original error message.

    Returns:
        A cleaned error message with only the relevant parts.
    """
    # For validation errors, extract just the field and reason
    if "validation error for Rule" in error_message or "validation errors for Rule" in error_message:
        # Extract error count
        error_count_match = re.search(r'(\d+) validation error', error_message)
        error_count = error_count_match.group(1) if error_count_match else "Multiple"

        # Extract missing fields
        missing_fields = []
        for line in error_message.split('\n'):
            # Get field paths (e.g., platforms.macOS.enforcement_info.check)
            if not line.startswith(' ') and '.' in line and 'Error validating' not in line:
                field = line.strip()
                missing_fields.append(field)

        if missing_fields:
            return f"{error_count} validation errors: Missing required fields: {', '.join(missing_fields)}"
        else:
            return f"{error_count} validation errors in rule schema"

    # For YAML parse errors
    elif "Error parsing YAML" in error_message:
        return "YAML syntax error in rule file"

    # For other errors
    return error_message.split('\n')[0]


def create_error_result(rule_id: str, file_path: str, error_message: str) -> Dict[str, Any]:
    """
    Create a result dictionary for a rule that had parsing errors.

    Args:
        rule_id: The ID of the rule.
        file_path: The path to the rule file.
        error_message: The error message.

    Returns:
        A dictionary with error information.
    """
    # Extract just the filename from the path
    filename = file_path.split('/')[-1] if '/' in file_path else file_path

    # Clean the error message
    cleaned_error = clean_error_message(error_message)

    return {
        "id": rule_id,
        "title": f"Error in rule: {filename}",
        "valid": False,
        "errors": [cleaned_error]
    }


class RuleParser:
    """
    Utility class to parse and validate macOS Security Compliance Project rules.
    """

    def __init__(self, rules_dir: Optional[Union[str, Path]] = None):
        """
        Initialize the rule parser with the directory containing rule files.

        Args:
            rules_dir: Path to the directory containing rule files. If None,
                      uses the default rules directory from the repo structure.
        """
        if rules_dir is None:
            # Default to the repository structure if no path provided
            # Now mscp is under scripts/, so repo root is three directories up from this file
            repo_root = Path(__file__).parent.parent.parent.parent
            self.rules_dir = repo_root / "rules"
        else:
            self.rules_dir = Path(rules_dir)

        if not self.rules_dir.exists() or not self.rules_dir.is_dir():
            raise ValueError(f"Rules directory does not exist: {self.rules_dir}")

    def _load_yaml(self, file_path: Path) -> Dict[str, Any]:
        """
        Load and parse a YAML file.

        Args:
            file_path: Path to the YAML file.

        Returns:
            The parsed YAML content as a Python dictionary.
        """
        with open(file_path, 'r') as f:
            try:
                return yaml.safe_load(f)
            except yaml.YAMLError as e:
                raise ValueError(f"Error parsing YAML file {file_path}: {e}")

    def parse_rule(self, file_path: Union[str, Path]) -> Rule:
        """
        Parse a single rule file and validate it against the schema.

        Args:
            file_path: Path to the rule YAML file.

        Returns:
            A validated Rule object.
        """
        path = Path(file_path)
        if not path.exists():
            raise FileNotFoundError(f"Rule file not found: {path}")

        # Load the YAML content
        rule_data = self._load_yaml(path)

        # Validate the rule ID matches the filename
        rule_id = rule_data.get('id')
        expected_filename = f"{rule_id}.yaml"
        if path.name != expected_filename:
            raise ValueError(
                f"Rule ID '{rule_id}' does not match the filename '{path.name}'. "
                f"Expected filename: '{expected_filename}'"
            )

        # Parse and validate the rule using Pydantic
        try:
            return Rule.model_validate(rule_data)
        except Exception as e:
            raise ValueError(f"Error validating rule {path}: {e}")

    def parse_rule_with_validation(self, file_path: Union[str, Path]) -> Dict[str, Any]:
        """
        Parse a single rule file with error handling.

        Args:
            file_path: Path to the rule YAML file.

        Returns:
            A dictionary with either a valid Rule object or error information.
        """
        path = Path(file_path)
        rule_id = path.stem  # Default to the filename without extension

        try:
            # Get the parsed rule
            rule = self.parse_rule(path)

            # Return success result
            return {
                "id": rule.id,
                "title": rule.title,
                "rule": rule,
                "valid": True,
                "errors": []
            }
        except Exception as e:
            # Return error result
            return create_error_result(rule_id, str(path), str(e))

    def get_rule_files(self, category: Optional[str] = None) -> List[Path]:
        """
        Get a list of rule files in the rules directory, optionally filtered by category.

        Args:
            category: Optional category to filter rules (e.g., 'audit', 'os', etc.)

        Returns:
            A list of Path objects for the rule files.
        """
        if category:
            category_dir = self.rules_dir / category
            if not category_dir.exists() or not category_dir.is_dir():
                raise ValueError(f"Category directory not found: {category_dir}")
            return list(category_dir.glob("*.yaml"))

        # Get all rule files from all categories
        rule_files = []
        for category_dir in self.rules_dir.iterdir():
            if category_dir.is_dir():
                rule_files.extend(category_dir.glob("*.yaml"))
        return rule_files

    def parse_rules(self, category: Optional[str] = None) -> Iterator[Rule]:
        """
        Parse and validate all rules in the rules directory, optionally filtered by category.
        Logs errors but doesn't yield invalid rules.

        Args:
            category: Optional category to filter rules (e.g., 'audit', 'os', etc.)

        Yields:
            Validated Rule objects.
        """
        rule_files = self.get_rule_files(category)
        for rule_file in rule_files:
            try:
                yield self.parse_rule(rule_file)
            except Exception as e:
                # Log the error and continue with the next rule
                print(f"Error parsing rule {rule_file}: {e}")

    def parse_rules_with_validation(self, category: Optional[str] = None,
                                   only_invalid: bool = False) -> Iterator[Dict[str, Any]]:
        """
        Parse and validate all rules in the rules directory, optionally filtered by category.
        Returns both valid and invalid rules as dictionaries.

        Args:
            category: Optional category to filter rules (e.g., 'audit', 'os', etc.)
            only_invalid: If True, yield only invalid rules

        Yields:
            Dictionaries containing either valid Rule objects or error information.
        """
        rule_files = self.get_rule_files(category)
        for rule_file in rule_files:
            result = self.parse_rule_with_validation(rule_file)

            # Filter based on only_invalid flag
            if not only_invalid or not result["valid"]:
                yield result

    def get_rule_by_id(self, rule_id: str) -> Optional[Rule]:
        """
        Find and parse a rule by its ID.

        Args:
            rule_id: The ID of the rule to find.

        Returns:
            The parsed Rule object, or None if the rule is not found.
        """
        for category_dir in self.rules_dir.iterdir():
            if category_dir.is_dir():
                rule_file = category_dir / f"{rule_id}.yaml"
                if rule_file.exists():
                    return self.parse_rule(rule_file)

        return None

    def get_rule_by_id_with_validation(self, rule_id: str) -> Dict[str, Any]:
        """
        Find and parse a rule by its ID with error handling.

        Args:
            rule_id: The ID of the rule to find.

        Returns:
            A dictionary with either a valid Rule object or error information.
        """
        for category_dir in self.rules_dir.iterdir():
            if category_dir.is_dir():
                rule_file = category_dir / f"{rule_id}.yaml"
                if rule_file.exists():
                    return self.parse_rule_with_validation(rule_file)

        # Rule not found
        return {
            "id": rule_id,
            "title": f"Rule not found: {rule_id}",
            "valid": False,
            "errors": [f"Rule ID '{rule_id}' not found in any category directory"]
        }