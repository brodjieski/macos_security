from typing import Dict, List, Optional, Any
from pydantic import BaseModel, Field

from .platforms import Platforms
from .references import References
from .payloads import MobileConfigDef, DDMDef


class Rule(BaseModel):
    """
    Pydantic model representing a macOS Security Compliance Project rule.
    Each rule defines security configurations and requirements for Apple platforms.
    """
    id: str = Field(..., description="Unique identifier for each rule")
    title: str = Field(..., description="Title of the rule as it will appear in the documentation")
    discussion: str = Field(..., description="Description of the rule, rationale, or other information")
    references: References
    platforms: Platforms

    tags: Optional[List[str]] = Field(None, description="Metadata keywords for searching and cross-referencing")
    odv: Optional[Dict[str, Any]] = Field(None, description="Organization Defined Values determined by a benchmark")
    mobileconfig_info: Optional[MobileConfigDef] = None
    ddm_info: Optional[DDMDef] = None

    def get_benchmarks(self) -> List[str]:
        """
        Get all benchmarks this rule belongs to across all platforms and versions.

        Returns:
            List of unique benchmark names.
        """
        benchmarks = set()

        # Extract from macOS platform
        if self.platforms.macOS:
            # Handle direct enforcement info (applies to all versions)
            if (hasattr(self.platforms.macOS, "enforcement_info") and
                self.platforms.macOS.enforcement_info):
                pass  # No benchmark at this level

            # Handle version-specific benchmarks
            for field_name in ['os_13_0', 'os_14_0', 'os_15_0']:
                version_obj = getattr(self.platforms.macOS, field_name, None)
                if version_obj and hasattr(version_obj, "benchmarks") and version_obj.benchmarks:
                    for benchmark in version_obj.benchmarks:
                        benchmarks.add(benchmark.name)

        # Extract from iOS platform
        if self.platforms.iOS:
            for field_name in ['os_16_0', 'os_17_0', 'os_18_0']:
                version_obj = getattr(self.platforms.iOS, field_name, None)
                if version_obj and hasattr(version_obj, "benchmarks") and version_obj.benchmarks:
                    for benchmark in version_obj.benchmarks:
                        benchmarks.add(benchmark.name)

        # Extract from visionOS platform
        if self.platforms.visionOS:
            for field_name in ['os_2_0']:
                version_obj = getattr(self.platforms.visionOS, field_name, None)
                if version_obj and hasattr(version_obj, "benchmarks") and version_obj.benchmarks:
                    for benchmark in version_obj.benchmarks:
                        benchmarks.add(benchmark.name)

        return sorted(list(benchmarks))

    def get_compliance_frameworks(self) -> List[str]:
        """
        Get all compliance frameworks this rule maps to from the tags field.

        Returns:
            List of compliance framework tags.
        """
        if not self.tags:
            return []

        # Common compliance framework prefixes
        framework_prefixes = [
            '800-53', 'cisv', 'cnssi', 'cmmc', 'disa', 'stig'
        ]

        # Filter tags that are likely compliance frameworks
        frameworks = [
            tag for tag in self.tags
            if any(tag.startswith(prefix) for prefix in framework_prefixes)
            or tag in ['800-171']
        ]

        return sorted(frameworks)

    class Config:
        """Configuration for the Rule model"""
        json_schema_extra = {
            "title": "macOS Security Compliance Project Rule",
            "description": "Schema for a macOS Security Compliance Project rule, detailing security configurations and requirements for Apple platforms.",
            "version": "2.0.0",
        }