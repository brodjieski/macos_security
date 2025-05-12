from typing import Dict, List, Optional, Any, Literal
from pydantic import BaseModel, Field, field_validator

from .common import BenchmarkItem, EnforcementInfo
from .payloads import MobileConfigDef, DDMDef


class OSDef(BaseModel):
    benchmarks: Optional[List[BenchmarkItem]] = None
    mobileconfig_info: Optional[MobileConfigDef] = None
    enforcement_info: Optional[EnforcementInfo] = None


class MacOSPlatform(BaseModel):
    enforcement_info: Optional[EnforcementInfo] = None
    os_13_0: Optional[OSDef] = Field(None, alias="13.0")
    os_14_0: Optional[OSDef] = Field(None, alias="14.0")
    os_15_0: Optional[OSDef] = Field(None, alias="15.0")
    introduced: Optional[str] = None
    
    @field_validator('introduced')
    def validate_introduced(cls, v):
        if v is not None and v != "-1":
            # Validate version format
            parts = v.split(".")
            if not (1 <= len(parts) <= 3) or not all(part.isdigit() for part in parts):
                raise ValueError(f"Invalid version format: {v}")
        return v


class IOSVersionDef(OSDef):
    supervised: Optional[bool] = None


class IOSPlatform(BaseModel):
    os_16_0: Optional[IOSVersionDef] = Field(None, alias="16.0")
    os_17_0: Optional[IOSVersionDef] = Field(None, alias="17.0")
    os_18_0: Optional[IOSVersionDef] = Field(None, alias="18.0")
    introduced: Optional[str] = None


class VisionOSPlatform(BaseModel):
    os_2_0: Optional[IOSVersionDef] = Field(None, alias="2.0")
    introduced: Optional[str] = None


class Platforms(BaseModel):
    macOS: Optional[MacOSPlatform] = None
    iOS: Optional[IOSPlatform] = None
    visionOS: Optional[VisionOSPlatform] = None