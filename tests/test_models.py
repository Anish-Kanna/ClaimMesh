import pytest
from uuid import UUID, uuid4

from app.models import EvidenceType, Verdict, ClaimScope, Evidence, Claim


def test_evidence_type_enum():
    # Valid values
    assert EvidenceType.SBOM.value == "SBOM"
    assert EvidenceType.VULN.value == "VULN"
    assert EvidenceType.SIG.value == "SIG"
    assert EvidenceType.PROV.value == "PROV"

    # Invalid value should raise ValueError
    with pytest.raises(ValueError):
        EvidenceType("invalid")


def test_evidence_model_valid():
    evidence = Evidence(
        id=uuid4(),
        type=EvidenceType.SBOM,
        subject="artifact:1.0.0",
        issuer="issuer@example.com",
        assertions={"component": "1.0"},
        srcHash="deadbeef",
        verification_status="verified",
        freshness_policy="policy-1",
        version="v1",
    )
    assert evidence.id is not None
    assert evidence.type == EvidenceType.SBOM
    assert evidence.subject == "artifact:1.0.0"
    assert evidence.verification_status == "verified"


def test_evidence_model_missing_required_fields():
    # Missing 'type' should raise ValidationError
    with pytest.raises(Exception) as exc:
        Evidence(
            id=uuid4(),
            # type omitted
            subject="artifact",
            issuer="issuer@example.com",
            assertions={},
            srcHash="deadbeef",
        )
    assert "type" in str(exc.value)


def test_claim_model_valid():
    claim = Claim(
        claim_id=uuid4(),
        version="1.0",
        target_artifact="artifact:1.0.0",
        scope=ClaimScope.DIRECT,
        required_predicates=["predicate-A"],
        consistency_constraints=["no-cycles"],
        revalidation={"interval": "24h"},
    )
    assert claim.claim_id is not None
    assert claim.version == "1.0"
    assert claim.scope == ClaimScope.DIRECT
    assert claim.required_predicates == ["predicate-A"]
    assert claim.consistency_constraints == ["no-cycles"]
    assert claim.revalidation == {"interval": "24h"}


def test_claim_model_missing_required_fields():
    with pytest.raises(Exception) as exc:
        Claim(
            # claim_id omitted -> should default to UUID4, but we need at least version, target_artifact, scope
            version="1.0",
            target_artifact="artifact:1.0.0",
            # scope omitted -> should default to ClaimScope.DIRECT? but we need to test missing required fields
            required_predicates=[],
        )
    # The model may allow missing claim_id because of default_factory, but missing target_artifact might be required
    # Let's test a more strict case: omit target_artifact (not optional)
    with pytest.raises(Exception) as exc:
        Claim(
            claim_id=uuid4(),
            version="1.0",
            # target_artifact omitted
            scope=ClaimScope.DIRECT,
            required_predicates=[],
        )
    assert "target_artifact" in str(exc.value)