from typing import Any, Dict, List, Optional, Union, Literal
from pydantic import BaseModel, Field, RootModel


class ArrayOfStrings(RootModel):
    root: List[str]


class ValidationHint(BaseModel):
    min: Optional[float] = None
    max: Optional[float] = None
    regex: Optional[str] = None
    enumValues: Optional[List[str]] = None


class ODVHint(BaseModel):
    datatype: str
    description: str
    validation: Optional[ValidationHint] = None


class ODV(BaseModel):
    hint: ODVHint
    recommended: Any  # Can be string, int, bool, list or object


class ResultDef(BaseModel):
    string: Optional[str] = None
    integer: Optional[Union[int, Literal["$ODV"]]] = None
    boolean: Optional[bool] = None


class CheckInfo(BaseModel):
    shell: str = Field(..., description="Shell command(s) to evaluate the state of a configuration")
    result: ResultDef
    additional_info: Optional[str] = None


class FixInfo(BaseModel):
    shell: str = Field(..., description="Shell command(s) to fix the configuration if the check command fails")
    additional_info: Optional[str] = None


class DefaultStateInfo(BaseModel):
    shell: Optional[str] = Field(None, description="Shell command(s) to restore the system to a default factory state")
    note: Optional[str] = None


class EnforcementInfo(BaseModel):
    check: CheckInfo
    fix: Optional[FixInfo] = None
    default_state: Optional[DefaultStateInfo] = None


class BenchmarkItem(BaseModel):
    name: str
    severity: Optional[Literal["high", "medium", "low"]] = None