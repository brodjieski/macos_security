import os
import json
from pathlib import Path
from typing import Dict, List, Optional, Union, Any, Tuple

from ..models import Rule


class RuleValidator:
    """
    Utility class for validating macOS Security Compliance Project rules.
    """
    
    def __init__(self, schema_path: Optional[Union[str, Path]] = None):
        """
        Initialize the rule validator with the JSON schema for rule validation.
        
        Args:
            schema_path: Path to the JSON schema file. If None, uses the default schema
                       from the repo structure.
        """
        if schema_path is None:
            # Default to the repository structure if no path provided
            # Now mscp is under scripts/, so repo root is three directories up from this file
            repo_root = Path(__file__).parent.parent.parent.parent
            self.schema_path = repo_root / "schema" / "mscp_rule.json"
        else:
            self.schema_path = Path(schema_path)
            
        if not self.schema_path.exists():
            raise FileNotFoundError(f"Schema file not found: {self.schema_path}")
        
        # Load the JSON schema
        with open(self.schema_path, 'r') as f:
            self.schema = json.load(f)
    
    def validate_rule(self, rule: Rule) -> Tuple[bool, List[str]]:
        """
        Validate a rule against the schema and perform additional business logic validation.
        
        Args:
            rule: The Rule object to validate.
            
        Returns:
            A tuple of (is_valid, error_messages) where is_valid is a boolean indicating
            whether the rule is valid, and error_messages is a list of validation error messages.
        """
        errors = []
        
        # Pydantic handles the schema validation automatically,
        # so we only need to implement additional business logic validation here
        
        # 1. Ensure rule ID matches a valid pattern
        if not rule.id:
            errors.append("Rule ID is required")
        
        # 2. Check if required fields are present
        # (This is already handled by Pydantic)
        
        # 3. Validate platform-specific configurations
        self._validate_platforms(rule, errors)
        
        # 4. Validate references
        self._validate_references(rule, errors)
        
        # Return validation results
        return len(errors) == 0, errors
    
    def _validate_platforms(self, rule: Rule, errors: List[str]) -> None:
        """
        Validate platform-specific configurations in the rule.
        
        Args:
            rule: The Rule object to validate.
            errors: List to append validation errors to.
        """
        if not rule.platforms:
            errors.append("Platforms configuration is required")
            return
        
        # Check if at least one platform is defined
        platforms = [p for p in [rule.platforms.macOS, rule.platforms.iOS, rule.platforms.visionOS] if p is not None]
        if not platforms:
            errors.append("At least one platform must be defined")
        
        # Validate macOS platform if present
        if rule.platforms.macOS:
            self._validate_macos_platform(rule, errors)
        
        # Validate iOS platform if present
        if rule.platforms.iOS:
            self._validate_ios_platform(rule, errors)
        
        # Validate visionOS platform if present
        if rule.platforms.visionOS:
            self._validate_visionos_platform(rule, errors)
    
    def _validate_macos_platform(self, rule: Rule, errors: List[str]) -> None:
        """
        Validate macOS platform-specific configurations.
        
        Args:
            rule: The Rule object to validate.
            errors: List to append validation errors to.
        """
        # Check if at least one macOS version is defined
        macos = rule.platforms.macOS
        versions = [v for v in [macos.os_13_0, macos.os_14_0, macos.os_15_0] if v is not None]
        
        if not versions and not macos.enforcement_info:
            errors.append("At least one macOS version or platform-level enforcement_info must be defined")
        
        # Check if enforcement_info is properly defined
        if macos.enforcement_info:
            self._validate_enforcement_info(macos.enforcement_info, "macOS", errors)
        
        # Validate each defined version
        for version_name, version in [
            ("13.0", macos.os_13_0),
            ("14.0", macos.os_14_0),
            ("15.0", macos.os_15_0),
        ]:
            if version and version.enforcement_info:
                self._validate_enforcement_info(version.enforcement_info, f"macOS {version_name}", errors)
    
    def _validate_ios_platform(self, rule: Rule, errors: List[str]) -> None:
        """
        Validate iOS platform-specific configurations.
        
        Args:
            rule: The Rule object to validate.
            errors: List to append validation errors to.
        """
        # Check if at least one iOS version is defined
        ios = rule.platforms.iOS
        versions = [v for v in [ios.os_16_0, ios.os_17_0, ios.os_18_0] if v is not None]
        
        if not versions:
            errors.append("At least one iOS version must be defined")
        
        # Validate each defined version
        for version_name, version in [
            ("16.0", ios.os_16_0),
            ("17.0", ios.os_17_0),
            ("18.0", ios.os_18_0),
        ]:
            if version and version.enforcement_info:
                self._validate_enforcement_info(version.enforcement_info, f"iOS {version_name}", errors)
    
    def _validate_visionos_platform(self, rule: Rule, errors: List[str]) -> None:
        """
        Validate visionOS platform-specific configurations.
        
        Args:
            rule: The Rule object to validate.
            errors: List to append validation errors to.
        """
        # Check if visionOS 2.0 is defined
        visionos = rule.platforms.visionOS
        
        if not visionos.os_2_0:
            errors.append("visionOS 2.0 must be defined")
        
        # Validate enforcement_info if present
        if visionos.os_2_0 and visionos.os_2_0.enforcement_info:
            self._validate_enforcement_info(visionos.os_2_0.enforcement_info, "visionOS 2.0", errors)
    
    def _validate_enforcement_info(self, enforcement_info, platform_name: str, errors: List[str]) -> None:
        """
        Validate enforcement_info section.
        
        Args:
            enforcement_info: The EnforcementInfo object to validate.
            platform_name: Name of the platform for error messages.
            errors: List to append validation errors to.
        """
        # Check if check command is defined
        if not enforcement_info.check:
            errors.append(f"{platform_name} enforcement_info requires a check section")
        
        # Check if check.shell is defined
        if not enforcement_info.check.shell:
            errors.append(f"{platform_name} enforcement_info.check requires a shell command")
        
        # Check if check.result is defined
        if not enforcement_info.check.result:
            errors.append(f"{platform_name} enforcement_info.check requires a result section")
        
        # Check if at least one result type is defined
        result = enforcement_info.check.result
        if not (result.string is not None or result.integer is not None or result.boolean is not None):
            errors.append(f"{platform_name} enforcement_info.check.result requires at least one result type")
    
    def _validate_references(self, rule: Rule, errors: List[str]) -> None:
        """
        Validate references section.
        
        Args:
            rule: The Rule object to validate.
            errors: List to append validation errors to.
        """
        # Check if NIST references are defined
        if not rule.references.nist:
            errors.append("NIST references are required")
        
        # Check if CCE references are defined
        if not rule.references.nist.cce:
            errors.append("CCE references are required")
        
        # Additional reference validations can be added here as needed