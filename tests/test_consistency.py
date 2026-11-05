import pytest
from datetime import datetime, timezone, timedelta
from uuid import uuid4

from app.models import Evidence, EvidenceType
from app.consistency import (
    ConsistencyChecker,
    check_consistency,
    Conflict,
    ConflictType,
    ConflictStatus,
    HashMismatchRule,
    VersionMismatchRule,
    ProvenanceSubjectMismatchRule,
    VulnerabilityAssertionConflictRule,
    SignerIdentityConflictRule,
    ValidityIntervalConflictRule,
    group_evidence_for_comparison,
    normalize_artifact_id,
    normalize_version_scope,
    are_comparable,
)


# ============================================================================
# Fixtures
# ============================================================================

@pytest.fixture
def sample_evidence_same_artifact():
    """Evidence for the same artifact with compatible scope."""
    artifact_id = "pkg:example@1.0.0"
    return [
        Evidence(
            id=uuid4(),
            type=EvidenceType.SBOM,
            subject=artifact_id,
            issuer="sbom-gen-1",
            assertions={"version": "1.0.0", "digest": "sha256:abc123"},
            srcHash="hash1",
            verification_status="verified",
        ),
        Evidence(
            id=uuid4(),
            type=EvidenceType.SBOM,
            subject=artifact_id,
            issuer="sbom-gen-2",
            assertions={"version": "1.0.0", "digest": "sha256:abc123"},
            srcHash="hash2",  # Different hash -> HASH_MISMATCH
            verification_status="verified",
        ),
    ]


@pytest.fixture
def sample_evidence_different_artifacts():
    """Evidence for different artifacts (should not be compared)."""
    return [
        Evidence(
            id=uuid4(),
            type=EvidenceType.SBOM,
            subject="pkg:foo@1.0.0",
            issuer="sbom-gen-1",
            assertions={"version": "1.0.0"},
            srcHash="hash1",
        ),
        Evidence(
            id=uuid4(),
            type=EvidenceType.SBOM,
            subject="pkg:bar@2.0.0",
            issuer="sbom-gen-2",
            assertions={"version": "2.0.0"},
            srcHash="hash2",
        ),
    ]


@pytest.fixture
def sample_evidence_same_artifact_different_versions():
    """Evidence for same artifact name but different versions."""
    return [
        Evidence(
            id=uuid4(),
            type=EvidenceType.SBOM,
            subject="pkg:example@1.0.0",
            issuer="sbom-gen-1",
            assertions={"version": "1.0.0"},
            srcHash="hash1",
        ),
        Evidence(
            id=uuid4(),
            type=EvidenceType.SBOM,
            subject="pkg:example@2.0.0",
            issuer="sbom-gen-2",
            assertions={"version": "2.0.0"},
            srcHash="hash2",
        ),
    ]


@pytest.fixture
def vuln_evidence_same_cve_conflicting():
    """VULN evidence for same CVE with conflicting severity."""
    artifact_id = "pkg:example@1.0.0"
    return [
        Evidence(
            id=uuid4(),
            type=EvidenceType.VULN,
            subject=artifact_id,
            issuer="scanner-1",
            assertions={"cve": "CVE-2024-1234", "severity": "HIGH", "affected_versions": ">=1.0.0 <1.1.0"},
            srcHash="vuln1",
            verification_status="verified",
        ),
        Evidence(
            id=uuid4(),
            type=EvidenceType.VULN,
            subject=artifact_id,
            issuer="scanner-2",
            assertions={"cve": "CVE-2024-1234", "severity": "MEDIUM", "affected_versions": ">=1.0.0 <1.1.0"},
            srcHash="vuln2",
            verification_status="verified",
        ),
    ]


@pytest.fixture
def prov_evidence_subject_mismatch():
    """PROV evidence with different subject digests."""
    artifact_id = "pkg:example@1.0.0"
    return [
        Evidence(
            id=uuid4(),
            type=EvidenceType.PROV,
            subject=artifact_id,
            issuer="builder-1",
            assertions={"subject_digest": "sha256:aaa", "slsa_level": 3},
            srcHash="prov1",
            verification_status="verified",
        ),
        Evidence(
            id=uuid4(),
            type=EvidenceType.PROV,
            subject=artifact_id,
            issuer="builder-2",
            assertions={"subject_digest": "sha256:bbb", "slsa_level": 3},
            srcHash="prov2",
            verification_status="verified",
        ),
    ]


@pytest.fixture
def sig_evidence_issuer_mismatch():
    """SIG evidence with different verified issuers."""
    artifact_id = "pkg:example@1.0.0"
    return [
        Evidence(
            id=uuid4(),
            type=EvidenceType.SIG,
            subject=artifact_id,
            issuer="cosign@example.com",
            assertions={"algorithm": "RSA"},
            srcHash="sig1",
            verification_status="verified",
        ),
        Evidence(
            id=uuid4(),
            type=EvidenceType.SIG,
            subject=artifact_id,
            issuer="different@example.com",
            assertions={"algorithm": "RSA"},
            srcHash="sig2",
            verification_status="verified",
        ),
    ]


@pytest.fixture
def evidence_validity_non_overlapping():
    """Evidence with non-overlapping validity intervals."""
    artifact_id = "pkg:example@1.0.0"
    now = datetime.now(timezone.utc)
    return [
        Evidence(
            id=uuid4(),
            type=EvidenceType.SBOM,
            subject=artifact_id,
            issuer="gen-1",
            assertions={"version": "1.0.0"},
            srcHash="h1",
            validity={"valid_from": (now - timedelta(days=10)).isoformat(), "valid_until": (now - timedelta(days=5)).isoformat()},
        ),
        Evidence(
            id=uuid4(),
            type=EvidenceType.SBOM,
            subject=artifact_id,
            issuer="gen-2",
            assertions={"version": "1.0.0"},
            srcHash="h2",
            validity={"valid_from": (now + timedelta(days=5)).isoformat(), "valid_until": (now + timedelta(days=10)).isoformat()},
        ),
    ]


@pytest.fixture
def clean_evidence_set():
    """Evidence with no conflicts."""
    artifact_id = "pkg:example@1.0.0"
    return [
        Evidence(
            id=uuid4(),
            type=EvidenceType.SBOM,
            subject=artifact_id,
            issuer="sbom-gen",
            assertions={"version": "1.0.0"},
            srcHash="samehash",
            verification_status="verified",
        ),
        Evidence(
            id=uuid4(),
            type=EvidenceType.VULN,
            subject=artifact_id,
            issuer="osv-scanner",
            assertions={"cve": "CVE-2024-5678", "severity": "LOW"},
            srcHash="vuln1",
            verification_status="verified",
        ),
    ]


# ============================================================================
# Normalization & Grouping Tests
# ============================================================================

def test_normalize_artifact_id():
    ev = Evidence(
        id=uuid4(),
        type=EvidenceType.SBOM,
        subject="pkg:example@1.0.0",
        issuer="test",
        assertions={},
        srcHash="h",
    )
    assert normalize_artifact_id(ev) == "pkg:example@1.0.0"


def test_normalize_version_scope():
    ev = Evidence(
        id=uuid4(),
        type=EvidenceType.SBOM,
        subject="pkg:example@1.0.0",
        issuer="test",
        assertions={"version": "1.0.0", "build_id": "build-123"},
        srcHash="h",
    )
    scope = normalize_version_scope(ev)
    assert "build-123" in scope
    assert "build:" in scope


def test_group_evidence_for_comparison(sample_evidence_same_artifact):
    groups = group_evidence_for_comparison(sample_evidence_same_artifact)
    assert len(groups) == 1
    group = list(groups.values())[0]
    assert len(group) == 2


def test_group_evidence_different_artifacts_not_grouped(sample_evidence_different_artifacts):
    groups = group_evidence_for_comparison(sample_evidence_different_artifacts)
    assert len(groups) == 2  # Two different artifacts


def test_are_comparable_true(sample_evidence_same_artifact):
    ev1, ev2 = sample_evidence_same_artifact
    assert are_comparable(ev1, ev2) is True


def test_are_comparable_false_different_artifact(sample_evidence_different_artifacts):
    ev1, ev2 = sample_evidence_different_artifacts
    assert are_comparable(ev1, ev2) is False


def test_are_comparable_false_different_version(sample_evidence_same_artifact_different_versions):
    ev1, ev2 = sample_evidence_same_artifact_different_versions
    assert are_comparable(ev1, ev2) is False


# ============================================================================
# Individual Rule Tests
# ============================================================================

def test_hash_mismatch_rule_detects(sample_evidence_same_artifact):
    rule = HashMismatchRule()
    ev1, ev2 = sample_evidence_same_artifact
    conflict = rule.check(ev1, ev2)
    assert conflict is not None
    assert conflict.type == ConflictType.HASH_MISMATCH
    assert conflict.field_path == "srcHash"
    assert conflict.severity == "HIGH"


def test_hash_mismatch_rule_no_conflict_when_same_hash():
    ev1 = Evidence(id=uuid4(), type=EvidenceType.SBOM, subject="pkg:a@1.0", issuer="i", assertions={"version": "1.0"}, srcHash="same", verification_status="verified")
    ev2 = Evidence(id=uuid4(), type=EvidenceType.SBOM, subject="pkg:a@1.0", issuer="i", assertions={"version": "1.0"}, srcHash="same", verification_status="verified")
    rule = HashMismatchRule()
    assert rule.check(ev1, ev2) is None


def test_version_mismatch_rule_detects():
    # Same artifact, SAME version scope, but different version assertions
    ev1 = Evidence(id=uuid4(), type=EvidenceType.SBOM, subject="pkg:a@1.0", issuer="i", assertions={"version": "1.0", "build_id": "build-1"}, srcHash="h1")
    ev2 = Evidence(id=uuid4(), type=EvidenceType.SBOM, subject="pkg:a@1.0", issuer="i", assertions={"version": "2.0", "build_id": "build-1"}, srcHash="h2")  # Same build, different version
    rule = VersionMismatchRule()
    conflict = rule.check(ev1, ev2)
    assert conflict is not None
    assert conflict.type == ConflictType.VERSION_MISMATCH
    assert conflict.field_path == "assertions.version"


def test_version_mismatch_rule_no_conflict_when_same_version():
    ev1 = Evidence(id=uuid4(), type=EvidenceType.SBOM, subject="pkg:a@1.0", issuer="i", assertions={"version": "1.0"}, srcHash="h1")
    ev2 = Evidence(id=uuid4(), type=EvidenceType.SBOM, subject="pkg:a@1.0", issuer="i", assertions={"version": "1.0"}, srcHash="h2")
    rule = VersionMismatchRule()
    assert rule.check(ev1, ev2) is None


def test_provenance_subject_mismatch_detects(prov_evidence_subject_mismatch):
    rule = ProvenanceSubjectMismatchRule()
    ev1, ev2 = prov_evidence_subject_mismatch
    conflict = rule.check(ev1, ev2)
    assert conflict is not None
    assert conflict.type == ConflictType.PROVENANCE_SUBJECT_MISMATCH
    assert "subject_digest" in conflict.field_path


def test_provenance_subject_mismatch_no_conflict_when_same():
    ev1 = Evidence(id=uuid4(), type=EvidenceType.PROV, subject="pkg:a@1.0", issuer="i", assertions={"subject_digest": "sha256:same"}, srcHash="h1", verification_status="verified")
    ev2 = Evidence(id=uuid4(), type=EvidenceType.PROV, subject="pkg:a@1.0", issuer="i", assertions={"subject_digest": "sha256:same"}, srcHash="h2", verification_status="verified")
    rule = ProvenanceSubjectMismatchRule()
    assert rule.check(ev1, ev2) is None


def test_vulnerability_assertion_conflict_severity(vuln_evidence_same_cve_conflicting):
    rule = VulnerabilityAssertionConflictRule()
    ev1, ev2 = vuln_evidence_same_cve_conflicting
    conflict = rule.check(ev1, ev2)
    assert conflict is not None
    assert conflict.type == ConflictType.VULNERABILITY_ASSERTION_CONFLICT
    assert conflict.field_path == "assertions.severity"
    assert conflict.severity == "MEDIUM"


def test_vulnerability_assertion_conflict_affected_versions():
    ev1 = Evidence(id=uuid4(), type=EvidenceType.VULN, subject="pkg:a@1.0", issuer="i", assertions={"cve": "CVE-1", "affected_versions": ">=1.0 <2.0"}, srcHash="h1", verification_status="verified")
    ev2 = Evidence(id=uuid4(), type=EvidenceType.VULN, subject="pkg:a@1.0", issuer="i", assertions={"cve": "CVE-1", "affected_versions": ">=2.0 <3.0"}, srcHash="h2", verification_status="verified")
    rule = VulnerabilityAssertionConflictRule()
    conflict = rule.check(ev1, ev2)
    assert conflict is not None
    assert conflict.type == ConflictType.VULNERABILITY_ASSERTION_CONFLICT
    assert "affected_versions" in conflict.field_path


def test_vulnerability_no_conflict_different_cve():
    ev1 = Evidence(id=uuid4(), type=EvidenceType.VULN, subject="pkg:a@1.0", issuer="i", assertions={"cve": "CVE-1", "severity": "HIGH"}, srcHash="h1", verification_status="verified")
    ev2 = Evidence(id=uuid4(), type=EvidenceType.VULN, subject="pkg:a@1.0", issuer="i", assertions={"cve": "CVE-2", "severity": "LOW"}, srcHash="h2", verification_status="verified")
    rule = VulnerabilityAssertionConflictRule()
    assert rule.check(ev1, ev2) is None


def test_signer_identity_conflict_detects(sig_evidence_issuer_mismatch):
    rule = SignerIdentityConflictRule()
    ev1, ev2 = sig_evidence_issuer_mismatch
    conflict = rule.check(ev1, ev2)
    assert conflict is not None
    assert conflict.type == ConflictType.SIGNER_IDENTITY_CONFLICT
    assert conflict.field_path == "issuer"
    assert conflict.severity == "HIGH"


def test_signer_identity_no_conflict_if_not_verified():
    ev1 = Evidence(id=uuid4(), type=EvidenceType.SIG, subject="pkg:a@1.0", issuer="a@a.com", assertions={}, srcHash="h1", verification_status="verified")
    ev2 = Evidence(id=uuid4(), type=EvidenceType.SIG, subject="pkg:a@1.0", issuer="b@b.com", assertions={}, srcHash="h2", verification_status="unverified")  # Not verified
    rule = SignerIdentityConflictRule()
    assert rule.check(ev1, ev2) is None


def test_validity_interval_conflict_detects(evidence_validity_non_overlapping):
    rule = ValidityIntervalConflictRule()
    ev1, ev2 = evidence_validity_non_overlapping
    conflict = rule.check(ev1, ev2)
    assert conflict is not None
    assert conflict.type == ConflictType.VALIDITY_INTERVAL_CONFLICT
    assert conflict.field_path == "validity"


def test_validity_interval_no_conflict_when_overlapping():
    now = datetime.now(timezone.utc)
    ev1 = Evidence(id=uuid4(), type=EvidenceType.SBOM, subject="pkg:a@1.0", issuer="i", assertions={}, srcHash="h1", validity={"valid_from": (now - timedelta(days=10)).isoformat(), "valid_until": (now + timedelta(days=10)).isoformat()})
    ev2 = Evidence(id=uuid4(), type=EvidenceType.SBOM, subject="pkg:a@1.0", issuer="i", assertions={}, srcHash="h2", validity={"valid_from": (now - timedelta(days=5)).isoformat(), "valid_until": (now + timedelta(days=5)).isoformat()})
    rule = ValidityIntervalConflictRule()
    assert rule.check(ev1, ev2) is None


def test_validity_interval_no_conflict_when_missing():
    ev1 = Evidence(id=uuid4(), type=EvidenceType.SBOM, subject="pkg:a@1.0", issuer="i", assertions={}, srcHash="h1", validity=None)
    ev2 = Evidence(id=uuid4(), type=EvidenceType.SBOM, subject="pkg:a@1.0", issuer="i", assertions={}, srcHash="h2", validity={"valid_from": "2024-01-01T00:00:00+00:00", "valid_until": "2024-12-31T23:59:59+00:00"})
    rule = ValidityIntervalConflictRule()
    assert rule.check(ev1, ev2) is None


# ============================================================================
# ConsistencyChecker Integration Tests
# ============================================================================

def test_check_consistency_hash_mismatch(sample_evidence_same_artifact):
    conflicts = check_consistency(sample_evidence_same_artifact)
    assert len(conflicts) == 1
    assert conflicts[0].type == ConflictType.HASH_MISMATCH
    assert conflicts[0].status == ConflictStatus.OPEN


def test_check_consistency_clean_set(clean_evidence_set):
    conflicts = check_consistency(clean_evidence_set)
    assert len(conflicts) == 0


def test_check_consistency_different_artifacts_no_comparison(sample_evidence_different_artifacts):
    conflicts = check_consistency(sample_evidence_different_artifacts)
    assert len(conflicts) == 0


def test_check_consistency_vuln_severity_conflict(vuln_evidence_same_cve_conflicting):
    conflicts = check_consistency(vuln_evidence_same_cve_conflicting)
    # Should detect both HASH_MISMATCH (different srcHash) and VULNERABILITY_ASSERTION_CONFLICT
    assert len(conflicts) >= 1
    types = {c.type for c in conflicts}
    assert ConflictType.VULNERABILITY_ASSERTION_CONFLICT in types


def test_check_consistency_prov_subject_mismatch(prov_evidence_subject_mismatch):
    conflicts = check_consistency(prov_evidence_subject_mismatch)
    # Should detect HASH_MISMATCH, PROVENANCE_SUBJECT_MISMATCH, and SIGNER_IDENTITY_CONFLICT
    assert len(conflicts) >= 1
    types = {c.type for c in conflicts}
    assert ConflictType.PROVENANCE_SUBJECT_MISMATCH in types


def test_check_consistency_signer_mismatch(sig_evidence_issuer_mismatch):
    conflicts = check_consistency(sig_evidence_issuer_mismatch)
    # Should detect HASH_MISMATCH and SIGNER_IDENTITY_CONFLICT
    assert len(conflicts) >= 1
    types = {c.type for c in conflicts}
    assert ConflictType.SIGNER_IDENTITY_CONFLICT in types


def test_check_consistency_validity_non_overlapping(evidence_validity_non_overlapping):
    conflicts = check_consistency(evidence_validity_non_overlapping)
    # Should detect HASH_MISMATCH and VALIDITY_INTERVAL_CONFLICT
    assert len(conflicts) >= 1
    types = {c.type for c in conflicts}
    assert ConflictType.VALIDITY_INTERVAL_CONFLICT in types


def test_check_consistency_multiple_conflicts():
    """Multiple conflict types in one evidence set."""
    artifact_id = "pkg:example@1.0.0"
    evidence = [
        Evidence(id=uuid4(), type=EvidenceType.SBOM, subject=artifact_id, issuer="i", assertions={"version": "1.0", "build_id": "build-1"}, srcHash="h1"),
        Evidence(id=uuid4(), type=EvidenceType.SBOM, subject=artifact_id, issuer="i", assertions={"version": "2.0", "build_id": "build-1"}, srcHash="h2"),  # VERSION_MISMATCH
        Evidence(id=uuid4(), type=EvidenceType.VULN, subject=artifact_id, issuer="i", assertions={"cve": "CVE-1", "severity": "HIGH"}, srcHash="v1", verification_status="verified"),
        Evidence(id=uuid4(), type=EvidenceType.VULN, subject=artifact_id, issuer="i", assertions={"cve": "CVE-1", "severity": "LOW"}, srcHash="v2", verification_status="verified"),  # VULN severity conflict
    ]
    conflicts = check_consistency(evidence)
    # Should detect VERSION_MISMATCH, VULNERABILITY_ASSERTION_CONFLICT, and HASH_MISMATCH
    types = {c.type for c in conflicts}
    assert ConflictType.VERSION_MISMATCH in types
    assert ConflictType.VULNERABILITY_ASSERTION_CONFLICT in types


def test_check_consistency_deterministic_ordering(sample_evidence_same_artifact):
    """Conflicts should be deterministically ordered."""
    checker = ConsistencyChecker()
    results = [checker.check_consistency(sample_evidence_same_artifact) for _ in range(3)]
    for r in results[1:]:
        assert [c.canonical_key() for c in r] == [c.canonical_key() for c in results[0]]


def test_check_consistency_empty_list():
    assert check_consistency([]) == []


def test_check_consistency_single_evidence():
    ev = Evidence(id=uuid4(), type=EvidenceType.SBOM, subject="pkg:a@1.0", issuer="i", assertions={}, srcHash="h")
    assert check_consistency([ev]) == []


def test_conflict_canonical_key_deterministic():
    """Same conflict should produce same canonical key."""
    c1 = Conflict(
        type=ConflictType.HASH_MISMATCH,
        artifact_id="pkg:a@1.0",
        evidence_ids=[uuid4(), uuid4()],
        field_path="srcHash",
        expected="h1",
        actual="h2",
        reason="test",
    )
    c2 = Conflict(
        type=ConflictType.HASH_MISMATCH,
        artifact_id="pkg:a@1.0",
        evidence_ids=[c1.evidence_ids[1], c1.evidence_ids[0]],  # reversed order
        field_path="srcHash",
        expected="h1",
        actual="h2",
        reason="test",
    )
    # canonical_key sorts evidence_ids, so should be same
    assert c1.canonical_key() == c2.canonical_key()


def test_conflict_model_fields():
    """Verify Conflict model has all required fields."""
    c = Conflict(
        type=ConflictType.HASH_MISMATCH,
        artifact_id="pkg:a@1.0",
        evidence_ids=[uuid4()],
        field_path="srcHash",
        expected="h1",
        actual="h2",
        reason="test",
    )
    assert c.id is not None
    assert c.type == ConflictType.HASH_MISMATCH
    assert c.status == ConflictStatus.OPEN
    assert c.detected_at is not None
    assert c.resolution_metadata == {}


def test_rule_registry_default_rules():
    from app.consistency import RuleRegistry
    registry = RuleRegistry()
    rules = registry.get_rules()
    assert len(rules) == 6
    rule_types = {r.conflict_type for r in rules}
    expected = {
        ConflictType.HASH_MISMATCH,
        ConflictType.VERSION_MISMATCH,
        ConflictType.PROVENANCE_SUBJECT_MISMATCH,
        ConflictType.VULNERABILITY_ASSERTION_CONFLICT,
        ConflictType.SIGNER_IDENTITY_CONFLICT,
        ConflictType.VALIDITY_INTERVAL_CONFLICT,
    }
    assert rule_types == expected


def test_evidence_from_different_issuers_not_auto_conflict():
    """Different issuers alone should not be a conflict without substantive disagreement."""
    artifact_id = "pkg:example@1.0.0"
    evidence = [
        Evidence(id=uuid4(), type=EvidenceType.SBOM, subject=artifact_id, issuer="issuer-1", assertions={"version": "1.0"}, srcHash="samehash"),
        Evidence(id=uuid4(), type=EvidenceType.SBOM, subject=artifact_id, issuer="issuer-2", assertions={"version": "1.0"}, srcHash="samehash"),
    ]
    conflicts = check_consistency(evidence)
    # No conflict because hash matches and version matches
    assert len(conflicts) == 0