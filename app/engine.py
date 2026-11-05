from __future__ import annotations

from dataclasses import dataclass, field
from datetime import datetime, timezone
from enum import Enum
from typing import Dict, List, Optional, Set, Any, Callable, Awaitable
from uuid import UUID, uuid4
import hashlib
import json

from app.models import Evidence, Claim, Verdict, EvidenceType
from app.graph import DependencyGraph


# ============================================================================
# Predicate Result & Registry
# ============================================================================

class PredicateResultStatus(str, Enum):
    PASS = "PASS"
    FAIL = "FAIL"
    UNKNOWN = "UNKNOWN"


@dataclass(frozen=True)
class PredicateResult:
    """Structured result of a single predicate evaluation."""
    predicate_id: str
    predicate_version: str
    artifact_id: UUID
    status: PredicateResultStatus
    reason_code: str
    evidence_ids: List[UUID] = field(default_factory=list)
    details: Dict[str, Any] = field(default_factory=dict)


@dataclass(frozen=True)
class PredicateSpec:
    """Specification of a predicate: its contract and parameter schema."""
    predicate_id: str
    version: str
    required_evidence_types: List[EvidenceType]
    supported_scopes: List[str]  # e.g., ["direct", "transitive", "shared"]
    parameter_schema: Dict[str, Any]  # JSON schema for parameters
    description: str


class PredicateRegistry:
    """Registry of predicate implementations by (predicate_id, version)."""

    def __init__(self):
        self._predicates: Dict[tuple[str, str], Callable] = {}
        self._specs: Dict[tuple[str, str], PredicateSpec] = {}

    def register(self, spec: PredicateSpec, evaluator: Callable) -> None:
        key = (spec.predicate_id, spec.version)
        if key in self._predicates:
            raise ValueError(f"Predicate already registered: {key}")
        self._specs[key] = spec
        self._predicates[key] = evaluator

    def get_evaluator(self, predicate_id: str, version: str) -> Callable:
        key = (predicate_id, version)
        if key not in self._predicates:
            raise KeyError(f"Predicate not found: {key}")
        return self._predicates[key]

    def get_spec(self, predicate_id: str, version: str) -> PredicateSpec:
        key = (predicate_id, version)
        if key not in self._specs:
            raise KeyError(f"Predicate spec not found: {key}")
        return self._specs[key]

    def list_predicates(self) -> List[PredicateSpec]:
        return list(self._specs.values())


# ============================================================================
# Evaluation Context (immutable, contains all verdict-determining inputs)
# ============================================================================

@dataclass(frozen=True)
class EvaluationContext:
    """
    Immutable context for a single claim evaluation.
    Contains ALL inputs that can affect the verdict.
    """
    claim: Claim
    target_artifact: UUID
    graph_fingerprint: str  # SHA-256 of canonical graph serialization
    closure: frozenset[UUID]
    evidence_snapshot: Dict[UUID, Evidence]  # relevant evidence by ID
    trust_policy_version: str
    freshness_policy_version: str
    predicate_versions: Dict[str, str]  # predicate_id -> version
    engine_version: str
    evaluation_time: datetime  # timezone-aware UTC
    consistency_conflicts: frozenset[str] = frozenset()  # conflict IDs from checker

    def canonical_fingerprint(self) -> str:
        """
        Compute a canonical SHA-256 fingerprint of ALL verdict-determining inputs.
        This is used as the memoization cache key.
        """
        # Build a deterministic dict representation
        data = {
            "claim_id": str(self.claim.claim_id),
            "claim_version": self.claim.version,
            "target_artifact": str(self.target_artifact),
            "graph_fingerprint": self.graph_fingerprint,
            "closure": sorted(str(u) for u in self.closure),
            "evidence": {
                str(eid): {
                    "type": ev.type.value,
                    "subject": ev.subject,
                    "issuer": ev.issuer,
                    "assertions": ev.assertions,
                    "validity": ev.validity,
                    "srcHash": ev.srcHash,
                    "verification_status": ev.verification_status,
                    "freshness_policy": ev.freshness_policy,
                    "version": ev.version,
                }
                for eid, ev in sorted(self.evidence_snapshot.items(), key=lambda x: str(x[0]))
            },
            "trust_policy_version": self.trust_policy_version,
            "freshness_policy_version": self.freshness_policy_version,
            "predicate_versions": dict(sorted(self.predicate_versions.items())),
            "engine_version": self.engine_version,
            "evaluation_time": self.evaluation_time.isoformat(),
            "consistency_conflicts": sorted(self.consistency_conflicts),
        }
        canonical = json.dumps(data, sort_keys=True, separators=(",", ":"), default=str)
        return hashlib.sha256(canonical.encode()).hexdigest()


# ============================================================================
# Trace Entry
# ============================================================================

@dataclass(frozen=True)
class TraceEntry:
    """Single entry in the evaluation trace."""
    predicate_id: str
    predicate_version: str
    artifact_id: UUID
    status: PredicateResultStatus
    reason_code: str
    evidence_ids: List[UUID]
    details: Dict[str, Any]
    cache_hit: bool = False


@dataclass(frozen=True)
class EvaluationResult:
    """Complete result of a claim evaluation."""
    claim_id: UUID
    claim_version: str
    target_artifact: UUID
    verdict: Verdict
    trace: List[TraceEntry]
    context_fingerprint: str
    evaluation_time: datetime
    cache_hit: bool = False


# ============================================================================
# Evidence Applicability
# ============================================================================

@dataclass(frozen=True)
class ApplicabilityResult:
    """Result of checking whether evidence is applicable to a predicate/artifact."""
    applicable: bool
    reason: str
    evidence_id: UUID
    checks: Dict[str, bool]  # individual check results


def evaluate_evidence_applicability(
    evidence: Evidence,
    predicate_spec: PredicateSpec,
    artifact_id: UUID,
    evaluation_time: datetime,
    freshness_policy: Dict[str, Any],
) -> ApplicabilityResult:
    """
    Check if evidence is applicable for a given predicate and artifact.
    Returns structured result with individual check outcomes.
    """
    checks = {}
    reasons = []

    # 1. Structural validity (always true if we have a parsed Evidence object)
    checks["structural_valid"] = True

    # 2. Artifact subject/scope match
    subject_match = evidence.subject == str(artifact_id) or str(artifact_id) in evidence.subject
    checks["artifact_match"] = subject_match
    if not subject_match:
        reasons.append(f"evidence subject {evidence.subject} does not match artifact {artifact_id}")

    # 3. Evidence type applicability
    type_applicable = evidence.type in predicate_spec.required_evidence_types
    checks["type_applicable"] = type_applicable
    if not type_applicable:
        reasons.append(f"evidence type {evidence.type.value} not in required types {[t.value for t in predicate_spec.required_evidence_types]}")

    # 4. Verification/trust status
    verified = evidence.verification_status == "verified"
    checks["verified"] = verified
    if not verified:
        reasons.append(f"evidence not verified (status: {evidence.verification_status})")

    # 5. Freshness at evaluation time
    fresh = True
    if evidence.validity and "valid_until" in evidence.validity:
        valid_until = evidence.validity["valid_until"]
        if isinstance(valid_until, str):
            valid_until = datetime.fromisoformat(valid_until.replace("Z", "+00:00"))
        if valid_until.tzinfo is None:
            valid_until = valid_until.replace(tzinfo=timezone.utc)
        fresh = evaluation_time <= valid_until
    checks["fresh"] = fresh
    if not fresh:
        reasons.append(f"evidence expired at {evidence.validity.get('valid_until')}")

    # 6. Version/hash binding (srcHash identifies the exact bytes)
    checks["has_src_hash"] = bool(evidence.srcHash)
    if not evidence.srcHash:
        reasons.append("evidence missing srcHash")

    applicable = all(checks.values())
    reason = "; ".join(reasons) if reasons else "all checks passed"

    return ApplicabilityResult(
        applicable=applicable,
        reason=reason,
        evidence_id=evidence.id,
        checks=checks,
    )


# ============================================================================
# Built-in Predicate Evaluators
# ============================================================================

def predicate_evidence_coverage_complete(
    context: EvaluationContext,
    artifact_id: UUID,
    parameters: Dict[str, Any],
    registry: PredicateRegistry,
) -> PredicateResult:
    """
    EVIDENCE_COVERAGE_COMPLETE: All required evidence types are present and applicable
    for the artifact (and its closure if scope is transitive/shared).
    """
    required_types = parameters.get("required_evidence_types", ["SBOM", "VULN", "SIG", "PROV"])
    if not required_types:
        return PredicateResult(
            predicate_id="EVIDENCE_COVERAGE_COMPLETE",
            predicate_version="1.0",
            artifact_id=artifact_id,
            status=PredicateResultStatus.UNKNOWN,
            reason_code="NO_REQUIRED_TYPES_SPECIFIED",
        )

    # For each required type, check if there's at least one applicable evidence
    missing_types = []
    found_evidence_ids = []

    for ev_type_str in required_types:
        ev_type = EvidenceType(ev_type_str)
        found = False
        for eid, ev in context.evidence_snapshot.items():
            if ev.type == ev_type and ev.subject == str(artifact_id):
                # Check applicability
                spec = registry.get_spec("EVIDENCE_COVERAGE_COMPLETE", "1.0")
                app = evaluate_evidence_applicability(ev, spec, artifact_id, context.evaluation_time, {})
                if app.applicable:
                    found = True
                    found_evidence_ids.append(eid)
                    break
        if not found:
            missing_types.append(ev_type_str)

    if missing_types:
        # Missing evidence -> UNKNOWN (not FAIL), per verdict semantics
        return PredicateResult(
            predicate_id="EVIDENCE_COVERAGE_COMPLETE",
            predicate_version="1.0",
            artifact_id=artifact_id,
            status=PredicateResultStatus.UNKNOWN,
            reason_code="MISSING_REQUIRED_EVIDENCE_TYPES",
            evidence_ids=found_evidence_ids,
            details={"missing_types": missing_types},
        )

    return PredicateResult(
        predicate_id="EVIDENCE_COVERAGE_COMPLETE",
        predicate_version="1.0",
        artifact_id=artifact_id,
        status=PredicateResultStatus.PASS,
        reason_code="ALL_REQUIRED_EVIDENCE_PRESENT",
        evidence_ids=found_evidence_ids,
    )


def predicate_no_high_severity_vulnerabilities(
    context: EvaluationContext,
    artifact_id: UUID,
    parameters: Dict[str, Any],
    registry: PredicateRegistry,
) -> PredicateResult:
    """
    NO_HIGH_SEVERITY_VULNERABILITIES: No applicable VULN evidence with severity >= threshold.
    """
    min_severity = parameters.get("min_severity", "HIGH").upper()
    severity_order = {"LOW": 1, "MEDIUM": 2, "HIGH": 3, "CRITICAL": 4}
    threshold = severity_order.get(min_severity, 3)

    violating_evidence = []
    checked_evidence = []

    for eid, ev in context.evidence_snapshot.items():
        if ev.type == EvidenceType.VULN and ev.subject == str(artifact_id):
            spec = registry.get_spec("NO_HIGH_SEVERITY_VULNERABILITIES", "1.0")
            app = evaluate_evidence_applicability(ev, spec, artifact_id, context.evaluation_time, {})
            if app.applicable:
                checked_evidence.append(eid)
                severity = ev.assertions.get("severity", "").upper()
                sev_level = severity_order.get(severity, 0)
                if sev_level >= threshold:
                    violating_evidence.append((eid, severity))

    if violating_evidence:
        return PredicateResult(
            predicate_id="NO_HIGH_SEVERITY_VULNERABILITIES",
            predicate_version="1.0",
            artifact_id=artifact_id,
            status=PredicateResultStatus.FAIL,
            reason_code="HIGH_SEVERITY_VULNERABILITY_FOUND",
            evidence_ids=[eid for eid, _ in violating_evidence],
            details={"violations": [{"evidence_id": str(eid), "severity": sev} for eid, sev in violating_evidence]},
        )

    return PredicateResult(
        predicate_id="NO_HIGH_SEVERITY_VULNERABILITIES",
        predicate_version="1.0",
        artifact_id=artifact_id,
        status=PredicateResultStatus.PASS,
        reason_code="NO_HIGH_SEVERITY_VULNERABILITIES",
        evidence_ids=checked_evidence,
    )


def predicate_valid_signature(
    context: EvaluationContext,
    artifact_id: UUID,
    parameters: Dict[str, Any],
    registry: PredicateRegistry,
) -> PredicateResult:
    """
    VALID_SIGNATURE: At least one applicable SIG evidence with verification_status == "verified"
    and trusted signer identity.
    """
    trusted_issuers = parameters.get("trusted_issuers", [])
    required_algorithm = parameters.get("algorithm")

    valid_sigs = []
    checked = []

    for eid, ev in context.evidence_snapshot.items():
        if ev.type == EvidenceType.SIG and ev.subject == str(artifact_id):
            spec = registry.get_spec("VALID_SIGNATURE", "1.0")
            app = evaluate_evidence_applicability(ev, spec, artifact_id, context.evaluation_time, {})
            if app.applicable:
                checked.append(eid)
                issuer_trusted = not trusted_issuers or ev.issuer in trusted_issuers
                algo_match = not required_algorithm or ev.assertions.get("algorithm") == required_algorithm
                if issuer_trusted and algo_match:
                    valid_sigs.append(eid)

    if not valid_sigs:
        return PredicateResult(
            predicate_id="VALID_SIGNATURE",
            predicate_version="1.0",
            artifact_id=artifact_id,
            status=PredicateResultStatus.FAIL if checked else PredicateResultStatus.UNKNOWN,
            reason_code="NO_TRUSTED_VALID_SIGNATURE" if checked else "NO_SIGNATURE_EVIDENCE",
            evidence_ids=checked,
        )

    return PredicateResult(
        predicate_id="VALID_SIGNATURE",
        predicate_version="1.0",
        artifact_id=artifact_id,
        status=PredicateResultStatus.PASS,
        reason_code="TRUSTED_VALID_SIGNATURE_FOUND",
        evidence_ids=valid_sigs,
    )


def predicate_valid_provenance(
    context: EvaluationContext,
    artifact_id: UUID,
    parameters: Dict[str, Any],
    registry: PredicateRegistry,
) -> PredicateResult:
    """
    VALID_PROVENANCE: At least one applicable PROV evidence with verified proof and matching subject.
    """
    required_slsa_level = parameters.get("min_slsa_level")

    valid_prov = []
    checked = []

    for eid, ev in context.evidence_snapshot.items():
        if ev.type == EvidenceType.PROV and ev.subject == str(artifact_id):
            spec = registry.get_spec("VALID_PROVENANCE", "1.0")
            app = evaluate_evidence_applicability(ev, spec, artifact_id, context.evaluation_time, {})
            if app.applicable:
                checked.append(eid)
                slsa_level = ev.assertions.get("slsa_level")
                level_ok = not required_slsa_level or (slsa_level and slsa_level >= required_slsa_level)
                if level_ok:
                    valid_prov.append(eid)

    if not valid_prov:
        return PredicateResult(
            predicate_id="VALID_PROVENANCE",
            predicate_version="1.0",
            artifact_id=artifact_id,
            status=PredicateResultStatus.FAIL if checked else PredicateResultStatus.UNKNOWN,
            reason_code="NO_VALID_PROVENANCE" if checked else "NO_PROVENANCE_EVIDENCE",
            evidence_ids=checked,
        )

    return PredicateResult(
        predicate_id="VALID_PROVENANCE",
        predicate_version="1.0",
        artifact_id=artifact_id,
        status=PredicateResultStatus.PASS,
        reason_code="VALID_PROVENANCE_FOUND",
        evidence_ids=valid_prov,
    )


def predicate_artifact_identity_match(
    context: EvaluationContext,
    artifact_id: UUID,
    parameters: Dict[str, Any],
    registry: PredicateRegistry,
) -> PredicateResult:
    """
    ARTIFACT_IDENTITY_MATCH: Evidence subject matches the exact artifact identity (digest/version).
    """
    expected_digest = parameters.get("expected_digest")
    expected_version = parameters.get("expected_version")

    matches = []
    checked = []

    for eid, ev in context.evidence_snapshot.items():
        if ev.subject == str(artifact_id):
            spec = registry.get_spec("ARTIFACT_IDENTITY_MATCH", "1.0")
            app = evaluate_evidence_applicability(ev, spec, artifact_id, context.evaluation_time, {})
            if app.applicable:
                checked.append(eid)
                digest_match = not expected_digest or ev.assertions.get("digest") == expected_digest
                version_match = not expected_version or ev.assertions.get("version") == expected_version
                if digest_match and version_match:
                    matches.append(eid)

    if not matches:
        return PredicateResult(
            predicate_id="ARTIFACT_IDENTITY_MATCH",
            predicate_version="1.0",
            artifact_id=artifact_id,
            status=PredicateResultStatus.FAIL if checked else PredicateResultStatus.UNKNOWN,
            reason_code="IDENTITY_MISMATCH" if checked else "NO_EVIDENCE_FOR_ARTIFACT",
            evidence_ids=checked,
        )

    return PredicateResult(
        predicate_id="ARTIFACT_IDENTITY_MATCH",
        predicate_version="1.0",
        artifact_id=artifact_id,
        status=PredicateResultStatus.PASS,
        reason_code="IDENTITY_MATCH_CONFIRMED",
        evidence_ids=matches,
    )


# ============================================================================
# Default Predicate Registry Setup
# ============================================================================

def create_default_registry() -> PredicateRegistry:
    """Create a registry with the built-in predicates."""
    registry = PredicateRegistry()

    # EVIDENCE_COVERAGE_COMPLETE
    registry.register(
        PredicateSpec(
            predicate_id="EVIDENCE_COVERAGE_COMPLETE",
            version="1.0",
            required_evidence_types=[EvidenceType.SBOM, EvidenceType.VULN, EvidenceType.SIG, EvidenceType.PROV],
            supported_scopes=["direct", "transitive", "shared"],
            parameter_schema={"type": "object", "properties": {"required_evidence_types": {"type": "array", "items": {"type": "string"}}}},
            description="All required evidence types are present and applicable for the artifact.",
        ),
        predicate_evidence_coverage_complete,
    )

    # NO_HIGH_SEVERITY_VULNERABILITIES
    registry.register(
        PredicateSpec(
            predicate_id="NO_HIGH_SEVERITY_VULNERABILITIES",
            version="1.0",
            required_evidence_types=[EvidenceType.VULN],
            supported_scopes=["direct", "transitive", "shared"],
            parameter_schema={"type": "object", "properties": {"min_severity": {"type": "string", "enum": ["LOW", "MEDIUM", "HIGH", "CRITICAL"]}}},
            description="No applicable vulnerability evidence with severity >= threshold.",
        ),
        predicate_no_high_severity_vulnerabilities,
    )

    # VALID_SIGNATURE
    registry.register(
        PredicateSpec(
            predicate_id="VALID_SIGNATURE",
            version="1.0",
            required_evidence_types=[EvidenceType.SIG],
            supported_scopes=["direct", "transitive", "shared"],
            parameter_schema={"type": "object", "properties": {"trusted_issuers": {"type": "array", "items": {"type": "string"}}, "algorithm": {"type": "string"}}},
            description="At least one verified signature from a trusted issuer.",
        ),
        predicate_valid_signature,
    )

    # VALID_PROVENANCE
    registry.register(
        PredicateSpec(
            predicate_id="VALID_PROVENANCE",
            version="1.0",
            required_evidence_types=[EvidenceType.PROV],
            supported_scopes=["direct", "transitive", "shared"],
            parameter_schema={"type": "object", "properties": {"min_slsa_level": {"type": "integer", "minimum": 1, "maximum": 4}}},
            description="At least one verified provenance attestation with matching subject.",
        ),
        predicate_valid_provenance,
    )

    # ARTIFACT_IDENTITY_MATCH
    registry.register(
        PredicateSpec(
            predicate_id="ARTIFACT_IDENTITY_MATCH",
            version="1.0",
            required_evidence_types=[EvidenceType.SBOM, EvidenceType.PROV, EvidenceType.SIG],
            supported_scopes=["direct", "transitive", "shared"],
            parameter_schema={"type": "object", "properties": {"expected_digest": {"type": "string"}, "expected_version": {"type": "string"}}},
            description="Evidence subject matches the exact artifact digest/version.",
        ),
        predicate_artifact_identity_match,
    )

    return registry


# ============================================================================
# Composite Memoization Cache
# ============================================================================

class EvaluationCache:
    """In-memory memoization cache keyed by canonical context fingerprint."""

    def __init__(self):
        self._cache: Dict[str, EvaluationResult] = {}

    def get(self, fingerprint: str) -> Optional[EvaluationResult]:
        return self._cache.get(fingerprint)

    def set(self, fingerprint: str, result: EvaluationResult) -> None:
        self._cache[fingerprint] = result

    def invalidate(self, fingerprint: str) -> bool:
        if fingerprint in self._cache:
            del self._cache[fingerprint]
            return True
        return False

    def clear(self) -> None:
        self._cache.clear()

    def __len__(self) -> int:
        return len(self._cache)


# ============================================================================
# Verdict Aggregation
# ============================================================================

def aggregate_verdicts(predicate_results: List[PredicateResult], required_predicates: List[str]) -> Verdict:
    """
    Aggregate predicate results into overall verdict.
    - PASS: ALL required predicates PASS
    - FAIL: ANY required predicate FAIL
    - UNKNOWN: otherwise (missing, insufficient, etc.)
    """
    # Map predicate_id -> result for required predicates
    required_results = {r.predicate_id: r for r in predicate_results if r.predicate_id in required_predicates}

    # Check for missing required predicates
    for req in required_predicates:
        if req not in required_results:
            return Verdict.UNKNOWN

    # Any required FAIL -> overall FAIL
    for result in required_results.values():
        if result.status == PredicateResultStatus.FAIL:
            return Verdict.FAIL

    # All required PASS -> overall PASS
    if all(r.status == PredicateResultStatus.PASS for r in required_results.values()):
        return Verdict.PASS

    # Otherwise UNKNOWN (some required are UNKNOWN)
    return Verdict.UNKNOWN


# ============================================================================
# Main Composition Engine
# ============================================================================

class CompositionEngine:
    """
    Deterministic claim composition engine.
    Evaluates a claim over its dependency closure using registered predicates.
    """

    def __init__(
        self,
        registry: Optional[PredicateRegistry] = None,
        cache: Optional[EvaluationCache] = None,
        engine_version: str = "1.0.0",
    ):
        self.registry = registry or create_default_registry()
        self.cache = cache or EvaluationCache()
        self.engine_version = engine_version

    def evaluate(
        self,
        claim: Claim,
        graph: DependencyGraph,
        evidence_store: Dict[UUID, Evidence],
        trust_policy_version: str = "1.0",
        freshness_policy_version: str = "1.0",
        evaluation_time: Optional[datetime] = None,
        consistency_conflicts: Optional[Set[str]] = None,
    ) -> EvaluationResult:
        """
        Evaluate a claim and return a deterministic EvaluationResult.
        """
        eval_time = evaluation_time or datetime.now(timezone.utc)

        # 1. Resolve target artifact deterministically from claim.target_artifact string
        # Use a deterministic UUID derived from the target_artifact string
        target_artifact = UUID(hashlib.sha256(claim.target_artifact.encode()).hexdigest()[:32])

        # 2. Compute closure
        try:
            closure = graph.closure(target_artifact)
        except KeyError:
            # Target not in graph - evaluate with empty closure
            closure = frozenset([target_artifact])

        # 3. Gather relevant evidence for artifacts in closure
        closure_strs = {str(aid) for aid in closure}
        relevant_evidence = {
            eid: ev for eid, ev in evidence_store.items()
            if ev.subject in closure_strs or any(aid_str in ev.subject for aid_str in closure_strs)
        }

        # 4. Compute graph fingerprint
        graph_fp = self._compute_graph_fingerprint(graph, closure)

        # 5. Build evaluation context
        predicate_versions = {}
        for pred_id in claim.required_predicates:
            # For now, assume version 1.0 for all predicates
            predicate_versions[pred_id] = "1.0"

        context = EvaluationContext(
            claim=claim,
            target_artifact=target_artifact,
            graph_fingerprint=graph_fp,
            closure=frozenset(closure),
            evidence_snapshot=relevant_evidence,
            trust_policy_version=trust_policy_version,
            freshness_policy_version=freshness_policy_version,
            predicate_versions=predicate_versions,
            engine_version=self.engine_version,
            evaluation_time=eval_time,
            consistency_conflicts=frozenset(consistency_conflicts or set()),
        )

        # 6. Check cache
        fingerprint = context.canonical_fingerprint()
        cached = self.cache.get(fingerprint)
        if cached:
            # Return cached result with cache_hit=True
            return EvaluationResult(
                claim_id=cached.claim_id,
                claim_version=cached.claim_version,
                target_artifact=cached.target_artifact,
                verdict=cached.verdict,
                trace=cached.trace,
                context_fingerprint=cached.context_fingerprint,
                evaluation_time=cached.evaluation_time,
                cache_hit=True,
            )

        # 7. Evaluate predicates for each artifact in closure (based on scope)
        artifacts_to_evaluate = self._determine_artifacts_to_evaluate(claim, closure, graph)

        all_predicate_results = []
        all_trace_entries = []

        for artifact_id in artifacts_to_evaluate:
            for pred_id in claim.required_predicates:
                pred_version = predicate_versions.get(pred_id, "1.0")
                try:
                    evaluator = self.registry.get_evaluator(pred_id, pred_version)
                except KeyError:
                    # Missing predicate implementation -> UNKNOWN
                    result = PredicateResult(
                        predicate_id=pred_id,
                        predicate_version=pred_version,
                        artifact_id=artifact_id,
                        status=PredicateResultStatus.UNKNOWN,
                        reason_code="PREDICATE_NOT_IMPLEMENTED",
                    )
                else:
                    # Get predicate parameters from claim (simplified - would be in claim spec)
                    parameters = {}
                    result = evaluator(context, artifact_id, parameters, self.registry)

                all_predicate_results.append(result)
                all_trace_entries.append(TraceEntry(
                    predicate_id=result.predicate_id,
                    predicate_version=result.predicate_version,
                    artifact_id=result.artifact_id,
                    status=result.status,
                    reason_code=result.reason_code,
                    evidence_ids=result.evidence_ids,
                    details=result.details,
                    cache_hit=False,
                ))

        # 8. Aggregate verdict
        verdict = aggregate_verdicts(all_predicate_results, claim.required_predicates)

        # 9. Build result
        result = EvaluationResult(
            claim_id=claim.claim_id,
            claim_version=claim.version,
            target_artifact=target_artifact,
            verdict=verdict,
            trace=all_trace_entries,
            context_fingerprint=fingerprint,
            evaluation_time=eval_time,
            cache_hit=False,
        )

        # 10. Cache result
        self.cache.set(fingerprint, result)

        return result

    def _compute_graph_fingerprint(self, graph: DependencyGraph, closure: frozenset[UUID]) -> str:
        """Compute SHA-256 fingerprint of the relevant subgraph."""
        # Get nodes and edges in closure
        nodes = sorted([str(n) for n in closure])
        edges = []
        for parent, child in graph.edges():
            if parent in closure and child in closure:
                edges.append((str(parent), str(child)))
        edges.sort()
        data = json.dumps({"nodes": nodes, "edges": edges}, sort_keys=True, separators=(",", ":"))
        return hashlib.sha256(data.encode()).hexdigest()

    def _determine_artifacts_to_evaluate(
        self,
        claim: Claim,
        closure: frozenset[UUID],
        graph: DependencyGraph,
    ) -> List[UUID]:
        """Determine which artifacts in the closure to evaluate based on claim scope."""
        scope = claim.scope.value if hasattr(claim.scope, 'value') else str(claim.scope)

        if scope == "direct":
            return [next(iter(closure))]  # just the target
        elif scope == "transitive":
            return list(closure)
        elif scope == "shared":
            # Shared dependencies = nodes with in-degree > 1 in the closure subgraph
            shared = []
            for node in closure:
                deps = graph.reverse_dependents(node)
                if len(deps & closure) > 1:
                    shared.append(node)
            return shared
        else:
            return list(closure)