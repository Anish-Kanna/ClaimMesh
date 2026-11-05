from __future__ import annotations

from enum import Enum
from datetime import datetime, timezone
from typing import Dict, List, Optional
from uuid import UUID, uuid4

from pydantic import BaseModel, Field


class EvidenceType(str, Enum):
    SBOM = "SBOM"
    VULN = "VULN"
    SIG = "SIG"
    PROV = "PROV"


class Verdict(str, Enum):
    PASS = "PASS"
    FAIL = "FAIL"
    UNKNOWN = "UNKNOWN"


class ClaimScope(str, Enum):
    DIRECT = "direct"
    TRANSITIVE = "transitive"
    SHARED = "shared"


class Evidence(BaseModel):
    id: UUID = Field(default_factory=uuid4)
    type: EvidenceType
    subject: str
    issuer: str
    assertions: Dict
    validity: Optional[dict] = None  # e.g., {"valid_from": datetime, "valid_until": datetime}
    srcHash: str
    verification_status: Optional[str] = None  # "verified", "unverified", etc.
    freshness_policy: Optional[str] = None  # reference to policy identifier
    version: Optional[str] = None
    # Additional fields can be added as the model evolves


class Claim(BaseModel):
    claim_id: UUID = Field(default_factory=uuid4)
    version: str
    target_artifact: str
    scope: ClaimScope
    required_predicates: List[str]
    consistency_constraints: List[str]
    revalidation: dict = Field(default_factory=dict)


class Verdict(str, Enum):
    PASS = "PASS"
    FAIL = "FAIL"
    UNKNOWN = "UNKNOWN"