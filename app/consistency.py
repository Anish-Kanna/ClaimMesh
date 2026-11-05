from __future__ import annotations

from dataclasses import dataclass, field
from datetime import datetime, timezone
from enum import Enum
from typing import Dict, List, Optional, Set, Any
from uuid import UUID, uuid4
import hashlib
import json

from app.models import Evidence, EvidenceType


# ============================================================================
# Conflict Types & Status
# ============================================================================

class ConflictType(str, Enum):
    HASH_MISMATCH = "HASH_MISMATCH"
    VERSION_MISMATCH = "VERSION_MISMATCH"
    PROVENANCE_SUBJECT_MISMATCH = "PROVENANCE_SUBJECT_MISMATCH"
    VULNERABILITY_ASSERTION_CONFLICT = "VULNERABILITY_ASSERTION_CONFLICT"
    SIGNER_IDENTITY_CONFLICT = "SIGNER_IDENTITY_CONFLICT"
    VALIDITY_INTERVAL_CONFLICT = "VALIDITY_INTERVAL_CONFLICT"


class ConflictStatus(str, Enum):
    OPEN = "OPEN"
    ACKNOWLEDGED = "ACKNOWLEDGED"
    RESOLVED = "RESOLVED"
    SUPPRESSED = "SUPPRESSED"


# ============================================================================
# Conflict Model
# ============================================================================

@dataclass(frozen=True)
class Conflict:
    """Structured conflict between evidence items."""
    id: UUID = field(default_factory=uuid4)
    type: ConflictType = ConflictType.HASH_MISMATCH
    artifact_id: str = ""  # normalized artifact identifier
    evidence_ids: List[UUID] = field(default_factory=list)
    field_path: str = ""  # JSON path to the conflicting field
    expected: Any = None
    actual: Any = None
    reason: str = ""
    severity: str = "HIGH"  # HIGH, MEDIUM, LOW
    detected_at: datetime = field(default_factory=lambda: datetime.now(timezone.utc))
    status: ConflictStatus = ConflictStatus.OPEN
    resolution_metadata: Dict[str, Any] = field(default_factory=dict)

    def canonical_key(self) -> str:
        """Deterministic key for deduplication."""
        data = {
            "type": self.type.value,
            "artifact_id": self.artifact_id,
            "evidence_ids": sorted(str(e) for e in self.evidence_ids),
            "field_path": self.field_path,
            "expected": self.expected,
            "actual": self.actual,
        }
        canonical = json.dumps(data, sort_keys=True, separators=(",", ":"), default=str)
        return hashlib.sha256(canonical.encode()).hexdigest()[:16]


# ============================================================================
# Comparability Logic
# ============================================================================

@dataclass(frozen=True)
class EvidenceGroupKey:
    """Key for grouping evidence that should be compared."""
    artifact_id: str
    version_scope: str  # normalized version/build scope
    evidence_type: EvidenceType

    def __hash__(self):
        return hash((self.artifact_id, self.version_scope, self.evidence_type))


def normalize_artifact_id(evidence: Evidence) -> str:
    """Extract normalized artifact identifier from evidence."""
    # In practice, this would parse subject for ecosystem/name/version/digest
    # For now, use subject as-is
    return evidence.subject


def normalize_version_scope(evidence: Evidence) -> str:
    """Extract version/build scope for comparability grouping.
    Uses build_id or digest, NOT version, so that version conflicts can be detected.
    """
    # Use build_id or digest for build scope; version is what we compare
    build = evidence.assertions.get("build_id") or evidence.assertions.get("digest") or "unknown"
    return f"build:{build}"


def group_evidence_for_comparison(evidence_list: List[Evidence]) -> Dict[EvidenceGroupKey, List[Evidence]]:
    """Group evidence by artifact, version scope, and type for comparison."""
    groups: Dict[EvidenceGroupKey, List[Evidence]] = {}
    for ev in evidence_list:
        key = EvidenceGroupKey(
            artifact_id=normalize_artifact_id(ev),
            version_scope=normalize_version_scope(ev),
            evidence_type=ev.type,
        )
        groups.setdefault(key, []).append(ev)
    return groups


def are_comparable(ev1: Evidence, ev2: Evidence) -> bool:
    """Check if two evidence items are comparable (same artifact, compatible scope)."""
    return (
        normalize_artifact_id(ev1) == normalize_artifact_id(ev2) and
        normalize_version_scope(ev1) == normalize_version_scope(ev2) and
        ev1.type == ev2.type
    )


# ============================================================================
# Conflict Rules
# ============================================================================

class ConflictRule:
    """Base class for conflict detection rules."""

    def __init__(self, rule_id: str, version: str, conflict_type: ConflictType):
        self.rule_id = rule_id
        self.version = version
        self.conflict_type = conflict_type

    def applies_to(self, ev1: Evidence, ev2: Evidence) -> bool:
        """Check if this rule applies to the evidence pair."""
        return are_comparable(ev1, ev2)

    def check(self, ev1: Evidence, ev2: Evidence) -> Optional[Conflict]:
        """Run the rule; return Conflict if detected, None otherwise."""
        raise NotImplementedError

    def get_field_path(self, field: str) -> str:
        return f"assertions.{field}"


class HashMismatchRule(ConflictRule):
    """Detect hash mismatches for the same artifact/build."""

    def __init__(self):
        super().__init__("HASH_MISMATCH", "1.0", ConflictType.HASH_MISMATCH)

    def check(self, ev1: Evidence, ev2: Evidence) -> Optional[Conflict]:
        if not self.applies_to(ev1, ev2):
            return None
        if ev1.srcHash and ev2.srcHash and ev1.srcHash != ev2.srcHash:
            return Conflict(
                type=self.conflict_type,
                artifact_id=normalize_artifact_id(ev1),
                evidence_ids=[ev1.id, ev2.id],
                field_path="srcHash",
                expected=ev1.srcHash,
                actual=ev2.srcHash,
                reason=f"Source hash mismatch for same artifact/build: {ev1.srcHash} vs {ev2.srcHash}",
                severity="HIGH",
            )
        return None


class VersionMismatchRule(ConflictRule):
    """Detect incompatible version assertions."""

    def __init__(self):
        super().__init__("VERSION_MISMATCH", "1.0", ConflictType.VERSION_MISMATCH)

    def check(self, ev1: Evidence, ev2: Evidence) -> Optional[Conflict]:
        if not self.applies_to(ev1, ev2):
            return None
        v1 = ev1.assertions.get("version")
        v2 = ev2.assertions.get("version")
        if v1 and v2 and v1 != v2:
            return Conflict(
                type=self.conflict_type,
                artifact_id=normalize_artifact_id(ev1),
                evidence_ids=[ev1.id, ev2.id],
                field_path=self.get_field_path("version"),
                expected=v1,
                actual=v2,
                reason=f"Version mismatch for same artifact: {v1} vs {v2}",
                severity="HIGH",
            )
        return None


class ProvenanceSubjectMismatchRule(ConflictRule):
    """Detect provenance subject not matching expected artifact."""

    def __init__(self):
        super().__init__("PROVENANCE_SUBJECT_MISMATCH", "1.0", ConflictType.PROVENANCE_SUBJECT_MISMATCH)

    def applies_to(self, ev1: Evidence, ev2: Evidence) -> bool:
        return ev1.type == EvidenceType.PROV and ev2.type == EvidenceType.PROV and are_comparable(ev1, ev2)

    def check(self, ev1: Evidence, ev2: Evidence) -> Optional[Conflict]:
        if not self.applies_to(ev1, ev2):
            return None
        # Compare provenance subject (e.g., build digest) if both have it
        sub1 = ev1.assertions.get("subject_digest") or ev1.assertions.get("build_digest")
        sub2 = ev2.assertions.get("subject_digest") or ev2.assertions.get("build_digest")
        if sub1 and sub2 and sub1 != sub2:
            return Conflict(
                type=self.conflict_type,
                artifact_id=normalize_artifact_id(ev1),
                evidence_ids=[ev1.id, ev2.id],
                field_path=self.get_field_path("subject_digest"),
                expected=sub1,
                actual=sub2,
                reason=f"Provenance subject digest mismatch: {sub1} vs {sub2}",
                severity="HIGH",
            )
        return None


class VulnerabilityAssertionConflictRule(ConflictRule):
    """Detect incompatible vulnerability assertions for same CVE/package/version."""

    def __init__(self):
        super().__init__("VULNERABILITY_ASSERTION_CONFLICT", "1.0", ConflictType.VULNERABILITY_ASSERTION_CONFLICT)

    def applies_to(self, ev1: Evidence, ev2: Evidence) -> bool:
        return ev1.type == EvidenceType.VULN and ev2.type == EvidenceType.VULN and are_comparable(ev1, ev2)

    def check(self, ev1: Evidence, ev2: Evidence) -> Optional[Conflict]:
        if not self.applies_to(ev1, ev2):
            return None
        # Compare CVE ID and affected package/version
        cve1 = ev1.assertions.get("cve") or ev1.assertions.get("vulnerability_id")
        cve2 = ev2.assertions.get("cve") or ev2.assertions.get("vulnerability_id")
        if cve1 and cve2 and cve1 == cve2:
            # Same CVE - check for conflicting assertions
            severity1 = ev1.assertions.get("severity")
            severity2 = ev2.assertions.get("severity")
            if severity1 and severity2 and severity1 != severity2:
                return Conflict(
                    type=self.conflict_type,
                    artifact_id=normalize_artifact_id(ev1),
                    evidence_ids=[ev1.id, ev2.id],
                    field_path=self.get_field_path("severity"),
                    expected=severity1,
                    actual=severity2,
                    reason=f"Conflicting severity for {cve1}: {severity1} vs {severity2}",
                    severity="MEDIUM",
                )
            # Check affected version ranges
            affected1 = ev1.assertions.get("affected_versions")
            affected2 = ev2.assertions.get("affected_versions")
            if affected1 and affected2 and affected1 != affected2:
                return Conflict(
                    type=self.conflict_type,
                    artifact_id=normalize_artifact_id(ev1),
                    evidence_ids=[ev1.id, ev2.id],
                    field_path=self.get_field_path("affected_versions"),
                    expected=affected1,
                    actual=affected2,
                    reason=f"Conflicting affected versions for {cve1}",
                    severity="MEDIUM",
                )
        return None


class SignerIdentityConflictRule(ConflictRule):
    """Detect signer identity mismatches for verified evidence."""

    def __init__(self):
        super().__init__("SIGNER_IDENTITY_CONFLICT", "1.0", ConflictType.SIGNER_IDENTITY_CONFLICT)

    def applies_to(self, ev1: Evidence, ev2: Evidence) -> bool:
        return (ev1.type in (EvidenceType.SIG, EvidenceType.PROV) and
                ev2.type in (EvidenceType.SIG, EvidenceType.PROV) and
                are_comparable(ev1, ev2))

    def check(self, ev1: Evidence, ev2: Evidence) -> Optional[Conflict]:
        if not self.applies_to(ev1, ev2):
            return None
        # Only compare if both are verified
        if ev1.verification_status != "verified" or ev2.verification_status != "verified":
            return None
        issuer1 = ev1.issuer
        issuer2 = ev2.issuer
        if issuer1 and issuer2 and issuer1 != issuer2:
            return Conflict(
                type=self.conflict_type,
                artifact_id=normalize_artifact_id(ev1),
                evidence_ids=[ev1.id, ev2.id],
                field_path="issuer",
                expected=issuer1,
                actual=issuer2,
                reason=f"Verified evidence has different issuers: {issuer1} vs {issuer2}",
                severity="HIGH",
            )
        return None


class ValidityIntervalConflictRule(ConflictRule):
    """Detect material validity interval disagreements."""

    def __init__(self):
        super().__init__("VALIDITY_INTERVAL_CONFLICT", "1.0", ConflictType.VALIDITY_INTERVAL_CONFLICT)

    def applies_to(self, ev1: Evidence, ev2: Evidence) -> bool:
        return are_comparable(ev1, ev2)

    def check(self, ev1: Evidence, ev2: Evidence) -> Optional[Conflict]:
        if not self.applies_to(ev1, ev2):
            return None
        v1 = ev1.validity
        v2 = ev2.validity
        if not v1 or not v2:
            return None
        # Check for non-overlapping intervals when both have valid_from/valid_until
        from1 = v1.get("valid_from")
        to1 = v1.get("valid_until")
        from2 = v2.get("valid_from")
        to2 = v2.get("valid_until")
        if from1 and to1 and from2 and to2:
            # Parse if strings
            if isinstance(from1, str):
                from1 = datetime.fromisoformat(from1.replace("Z", "+00:00"))
            if isinstance(to1, str):
                to1 = datetime.fromisoformat(to1.replace("Z", "+00:00"))
            if isinstance(from2, str):
                from2 = datetime.fromisoformat(from2.replace("Z", "+00:00"))
            if isinstance(to2, str):
                to2 = datetime.fromisoformat(to2.replace("Z", "+00:00"))
            # Check overlap
            if to1 < from2 or to2 < from1:
                return Conflict(
                    type=self.conflict_type,
                    artifact_id=normalize_artifact_id(ev1),
                    evidence_ids=[ev1.id, ev2.id],
                    field_path="validity",
                    expected={"valid_from": str(from1), "valid_until": str(to1)},
                    actual={"valid_from": str(from2), "valid_until": str(to2)},
                    reason=f"Non-overlapping validity intervals",
                    severity="MEDIUM",
                )
        return None


# ============================================================================
# Rule Registry
# ============================================================================

class RuleRegistry:
    """Registry of conflict detection rules."""

    def __init__(self):
        self._rules: List[ConflictRule] = []
        self._register_defaults()

    def _register_defaults(self):
        self.register(HashMismatchRule())
        self.register(VersionMismatchRule())
        self.register(ProvenanceSubjectMismatchRule())
        self.register(VulnerabilityAssertionConflictRule())
        self.register(SignerIdentityConflictRule())
        self.register(ValidityIntervalConflictRule())

    def register(self, rule: ConflictRule):
        self._rules.append(rule)

    def get_rules(self) -> List[ConflictRule]:
        return list(self._rules)

    def get_rules_for_type(self, evidence_type: EvidenceType) -> List[ConflictRule]:
        return [r for r in self._rules if r.applies_to.__self__.evidence_type == evidence_type]  # simplified


# ============================================================================
# Consistency Checker
# ============================================================================

class ConsistencyChecker:
    """
    Cross-evidence consistency checker.
    Detects explicit contradictions without choosing authoritative sources.
    """

    def __init__(self, registry: Optional[RuleRegistry] = None):
        self.registry = registry or RuleRegistry()

    def check_consistency(self, evidence_list: List[Evidence]) -> List[Conflict]:
        """
        Run all applicable rules on evidence groups and return detected conflicts.
        """
        if not evidence_list:
            return []

        # Group evidence by artifact/version/type for meaningful comparison
        groups = group_evidence_for_comparison(evidence_list)

        all_conflicts: List[Conflict] = []

        for key, group in groups.items():
            if len(group) < 2:
                continue  # Need at least 2 to compare

            # Compare each pair within the group
            for i in range(len(group)):
                for j in range(i + 1, len(group)):
                    ev1, ev2 = group[i], group[j]
                    # Run all applicable rules
                    for rule in self.registry.get_rules():
                        if rule.applies_to(ev1, ev2):
                            conflict = rule.check(ev1, ev2)
                            if conflict:
                                all_conflicts.append(conflict)

        # Deterministic deduplication and ordering
        unique_conflicts = self._deduplicate_conflicts(all_conflicts)
        unique_conflicts.sort(key=lambda c: (c.artifact_id, c.type.value, c.field_path, c.canonical_key()))

        return unique_conflicts

    def _deduplicate_conflicts(self, conflicts: List[Conflict]) -> List[Conflict]:
        """Remove duplicate conflicts based on canonical key."""
        seen: Set[str] = set()
        unique: List[Conflict] = []
        for c in conflicts:
            key = c.canonical_key()
            if key not in seen:
                seen.add(key)
                unique.append(c)
        return unique


# ============================================================================
# Convenience function
# ============================================================================

def check_consistency(evidence_list: List[Evidence]) -> List[Conflict]:
    """Module-level function for simple use."""
    checker = ConsistencyChecker()
    return checker.check_consistency(evidence_list)