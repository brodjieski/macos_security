from typing import Any, Dict, List, Optional, Union, Literal
from pydantic import BaseModel, Field, RootModel


class PayloadContent(RootModel):
    root: List[Dict[str, Any]]


class MobileConfigItem(BaseModel):
    PayloadType: str
    PayloadContent: PayloadContent


MobileConfigDef = List[MobileConfigItem]


class DDMDef(BaseModel):
    declarationtype: Optional[Literal[
        "com.apple.configuration.services.configuration-files",
        "com.apple.configuration.diskmanagement.settings", 
        "com.apple.configuration.passcode.settings"
    ]] = Field(None, alias="declaration_type")
    
    service: Optional[Literal[
        "com.apple.sshd",
        "com.apple.sudo",
        "com.apple.pam",
        "com.apple.cups",
        "com.apple.apache.httpd",
        "com.apple.bash",
        "com.apple.zsh"
    ]] = None
    
    config_file: Optional[str] = None
    configuration_key: Optional[str] = None
    configuration_value: Optional[Any] = None
    ddm_key: Optional[str] = None
    ddm_value: Optional[Any] = None