from typing import Dict, List, Optional, Any
from pydantic import BaseModel, Field, RootModel


class CCEReferences(RootModel):
    root: Dict[str, List[str]]


class NISTReferences(BaseModel):
    cce: CCEReferences
    """References to Common Configuration Enumeration identifiers"""
    
    cfr_800_53r5: Optional[List[str]] = Field(None, alias="800-53r5")
    """References to NIST Special Publication 800-53 Revision 5"""
    
    cfr_800_171r3: Optional[List[str]] = Field(None, alias="800-171r3")
    """References to NIST Special Publication 800-171 Revision 3"""


class DISAReferences(BaseModel):
    cci: Optional[List[str]] = None
    """References to DISA Control Correlation Identifier"""
    
    srg: Optional[List[str]] = None
    """References to DISA Security Requirements Guide"""
    
    disa_stig: Optional[Dict[str, List[str]]] = None
    """References to DISA Security Technical Implementation Guide"""
    
    cmmc: Optional[List[str]] = None
    """References to Cybersecurity Maturity Model Certification"""


class CISBenchmarkReferences(RootModel):
    root: Dict[str, List[str]]


class CISReferences(BaseModel):
    benchmark: Optional[CISBenchmarkReferences] = None
    """References to CIS Benchmarks"""
    
    controls_v8: Optional[List[Any]] = None
    """References to CIS Controls Version 8"""


class BSIReferences(BaseModel):
    indigo: Optional[Dict[str, List[str]]] = None
    """References to BSI IT-Grundschutz-Kompendium"""


class References(BaseModel):
    nist: NISTReferences
    """References to NIST publications and documents"""
    
    disa: Optional[DISAReferences] = None
    """References to DISA publications and documents"""
    
    cis: Optional[CISReferences] = None
    """References to CIS publications and documents"""
    
    bsi: Optional[BSIReferences] = None
    """References to BSI publications and documents"""