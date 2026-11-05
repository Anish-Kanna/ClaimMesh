# ClaimMesh — Level 2 Product Implementation Plan

**Status:** Implementation-ready baseline  
**Project type:** Final-year cybersecurity project and deployable software supply-chain evidence verification tool  
**Primary principle:** Deterministic security decisions; AI, if added later, is advisory only.

---

## 1. Product Goal

Build ClaimMesh as a functional, testable, deployable system that evaluates software supply-chain security claims using dependency-aware evidence composition.

The system will ingest evidence, associate it with the correct artifact, evaluate claims across dependency closures, detect contradictions and stale evidence, expose verdicts through an API, and enforce configurable CI/CD policy.

### Level 2 completion target

A completed Level 2 product must include:

- Typed evidence, claim, and verdict models.
- A dependency graph with closure computation and cycle detection.
- A deterministic composition engine with structured evaluation traces.
- Cross-evidence consistency checking.
- Temporal validity and targeted re-evaluation.
- Persistent storage for evidence, claims, verdicts, and conflicts.
- Real evidence ingestion for CycloneDX/SPDX SBOMs, OSV vulnerability data, Cosign signatures, and in-toto/SLSA provenance.
- A FastAPI API and explicit `PASS` / `FAIL` / `UNKNOWN` semantics.
- Configurable CI/CD policy mapping verdicts to `ALLOW`, `BLOCK`, or `RETRY`.
- Application-security controls, audit logging, and secret management.
- Reproducible Docker deployment.
- End-to-end evaluation against at least one real software project, plus reproducible benchmarks.
- A functional dashboard, implemented after the backend API and core integrations stabilize.

AI explanations, Neo4j, Kubernetes, and task queues are not required for the initial Level 2 release.

---

## 2. Architecture

The implementation follows this flow:

1. **Evidence sources** — SBOM tools, vulnerability feeds, signatures, provenance attestations, and later additional sources.
2. **Parsing and verification** — parse input formats; independently verify authenticity and artifact binding where applicable.
3. **Evidence normalization** — convert supported source data into the canonical Evidence model.
4. **Persistent evidence store** — store evidence and its provenance/verification status.
5. **Dependency graph** — represent artifact dependencies and calculate the in-scope closure.
6. **Claim specification** — define the artifact, scope, required predicates, consistency constraints, and revalidation rules.
7. **Deterministic composition engine** — evaluate claim predicates over relevant evidence.
8. **Consistency checker** — identify explicit conflicts between evidence items.
9. **Temporal validity and revalidation** — identify expired/changed evidence and re-evaluate affected claims.
10. **Verdict and explanation API** — return the verdict and a structured trace.
11. **CI/CD policy gate** — map verdicts to configured deployment actions.
12. **Deployment and dashboard** — package the service reproducibly and provide a UI that consumes the API.

**Security boundary:** The backend is the source of truth for verification decisions. Neither a dashboard nor an optional AI component may calculate, change, or override a security verdict.

---

## 3. Technology Stack

| Layer | Choice | Use |
|---|---|---|
| Language | Python 3.11 | Core implementation |
| API | FastAPI | HTTP API and OpenAPI schema |
| Models | Pydantic v2 | Validation and serialization |
| Graph | NetworkX | Dependency graph and closure |
| Storage | SQLAlchemy 2.0 + SQLite initially | Persistence behind a storage interface |
| Future database option | PostgreSQL | Consider only when justified |
| Tests | pytest + pytest-cov | Unit and integration tests |
| CI | GitHub Actions | Run tests and checks on pushes and pull requests |
| SBOM | Syft; CycloneDX/SPDX parsers | Generate and parse SBOMs |
| Vulnerabilities | OSV-Scanner / OSV data | Vulnerability evidence |
| Signatures | Cosign CLI | Image signature verification |
| Provenance | Supported in-toto/SLSA libraries and formats | Attestation parsing and verification |
| Security checks | pip-audit; pinned dependencies | Dependency risk checks |
| Deployment | Docker + docker-compose | Reproducible local/host deployment |
| Dashboard | React + TypeScript + Cytoscape.js | Graph and evidence visualization |

Do not introduce Neo4j, Kubernetes, or a task queue unless a concrete requirement appears.

---

## 4. Global Design Rules

### 4.1 Deterministic decisions

- Given identical normalized inputs, policy, evaluation time, and engine version, the engine must return the same verdict and trace.
- The engine must not call an LLM to decide a verdict.
- Keep the pure evaluation logic separate from FastAPI, persistence, and external command execution.
- Record enough evaluation metadata to explain and reproduce a result.

### 4.2 Verdict semantics

- **PASS:** All required predicates are supported by sufficient, applicable, authentic, current evidence; no required condition is disproven.
- **FAIL:** Applicable evidence establishes that at least one required condition is false.
- **UNKNOWN:** Evidence is missing, insufficient, stale, unauthenticated, contradictory in a way that prevents a sound decision, or cannot be bound to the target artifact.
- Missing evidence must never silently become PASS.
- Contradictory evidence should be surfaced as a conflict. If the contradiction prevents a sound claim decision, the verdict is UNKNOWN unless an explicit, documented policy resolves it.
- A failed verification check is not the same as missing evidence: retain the failure reason so the engine can apply the correct claim semantics.

### 4.3 Evidence parsing, authenticity, and trust

Keep these concepts distinct:

1. **Parsing:** Is the input structurally readable?
2. **Integrity:** Does its content hash match a trusted expected hash/reference, where one is available?
3. **Authenticity:** Does a cryptographic signature or proof verify?
4. **Artifact binding:** Does the verified evidence refer to the exact artifact/digest/version being evaluated?
5. **Trust policy:** Is the verified signer, issuer, builder, or source accepted under the project's configured policy?

Parsing success alone must never imply authenticity. A computed SHA-256 hash identifies the bytes that were read; it does not, by itself, prove that those bytes are trustworthy.

### 4.4 Memoization and invalidation

- Never key a verdict cache only by dependency closure.
- The key must include the canonical claim/specification and predicate configuration, closure identity, relevant evidence identifiers and content/version hashes, evidence verification and freshness state, trust-policy version/configuration, relevant evaluation time/validity inputs, and engine/rule version.
- Use stable canonical serialization before hashing structured inputs.
- A change to any verdict-affecting input must produce a cache miss or explicit invalidation.
- Tests must prove reuse for identical inputs and recomputation after any relevant input changes.

### 4.5 Security and operational requirements

- Never hardcode secrets.
- Validate all external input.
- Use safe error responses; detailed internal errors go to structured logs.
- Enforce project-level data isolation wherever multi-project data is supported.
- Invoke external tools with argument arrays (not shell-concatenated user input), controlled timeouts, and captured exit status/output.
- Pin or constrain dependencies and run dependency security checks in CI.
- Avoid claiming production readiness without appropriate testing and operational evidence.

---

## 5. Phase-by-Phase Roadmap

Every phase must be completed and tested before its work is treated as done. Keep commits small and review changes before merging.

### Phase 0 — Project Skeleton, CI Gate, and Health Check

**Goal:** Establish a minimal runnable FastAPI application and a clean-clone CI workflow.

**Tasks**
- Create the repository layout: `app/`, `tests/`, `scripts/`, `.github/workflows/`.
- Add `main.py` with:
  - `GET /health` → `{"status":"healthy","service":"ClaimMesh"}`
  - `GET /info` → basic project metadata.
- Add `tests/test_main.py` with endpoint tests.
- Add `requirements.txt` containing FastAPI, Uvicorn, Pydantic, NetworkX, pytest, and pytest-cov.
- Add a minimal README with install, test, and run commands.
- Add `.github/workflows/ci.yml` to install dependencies and run pytest on pushes and pull requests.

**Files**
- `main.py`
- `app/`
- `tests/test_main.py`
- `requirements.txt`
- `README.md`
- `.github/workflows/ci.yml`

**Tests**
- Health endpoint returns expected JSON and status.
- Info endpoint returns expected metadata.
- CI succeeds from a clean checkout.

**Exit criteria**
- Dependencies install successfully.
- `uvicorn main:app --reload` starts.
- `pytest` passes.
- GitHub Actions passes.

### Phase 1 — Core Data Models

**Goal:** Define validated, reusable models independently of the API and database.

**Tasks**
- Create `app/models.py`.
- Define `Evidence` with at least:
  - `id`
  - `type`
  - `subject`
  - `issuer`
  - `assertions`
  - `validity` / `valid_from` / `valid_until` as appropriate
  - `srcHash`
  - explicit parsing, integrity, authenticity, artifact-binding, and trust status/metadata where applicable.
- Define `PredicateModel` with a stable predicate identifier, type, parameters, and required/optional semantics.
- Define `ClaimSpecification` with target artifact, dependency scope, required predicates, consistency constraints, and revalidation rules.
- Define `Verdict` enum: `PASS`, `FAIL`, `UNKNOWN`.
- Define `TraceEntry` and conflict models.
- Use explicit types and validation; document allowed values.
- Avoid making a missing hash or absent signature look like a successful verification result.
- Add serialization/deserialization helpers only where they improve clarity.

**Files**
- `app/models.py`
- `tests/test_models.py`

**Tests**
- Valid and invalid models.
- Required fields and defaults.
- Serialization/deserialization.
- Invalid enum and malformed timestamp handling.
- Evidence status fields do not imply authenticity merely because parsing succeeded.

**Dependencies**
- Phase 0.

**Exit criteria**
- Models import cleanly and validate expected good/bad inputs.
- A minimal claim and evidence object can be constructed without FastAPI.

### Phase 2 — Dependency Graph and Closure

**Goal:** Represent artifact dependencies and compute a deterministic in-scope closure.

**Tasks**
- Create `app/graph.py` with a `DependencyGraph` wrapper around `networkx.DiGraph`.
- Implement dependency insertion and cycle detection.
- Implement `closure(node)` including the root artifact.
- Return stable/sorted output where ordering is observable.
- Define edge direction clearly and consistently (for example, `parent` depends on `child`).
- Reject new edges that create cycles, with a clear exception.
- Expose a small closure function for later engine/API use.

**Files**
- `app/graph.py`
- `tests/test_graph.py`

**Tests**
- Simple chain.
- Diamond graph with shared dependency.
- Isolated node.
- Unknown node.
- Cycle insertion rejected.
- Closure is deterministic.

**Dependencies**
- Phase 1.

**Exit criteria**
- Closure and cycle tests pass.
- Edge semantics are documented and consistently applied.

### Phase 3 — Deterministic Claim Composition Engine

**Goal:** Evaluate a claim over a dependency closure and return a deterministic verdict with a structured trace.

**Tasks**
- Create `app/engine.py`.
- Implement a pure core function equivalent to:
  `evaluate_claim(spec: ClaimSpecification, graph: DependencyGraph, evidence_store: dict) -> (Verdict, list[TraceEntry])`.
- Resolve the target artifact's closure and retrieve only evidence relevant to the target, closure, predicate, version, and claim scope.
- Implement predicate helpers, initially including examples such as:
  - `has_sufficient_vulnerability(ev, min_cvss)` or an equivalent vulnerability predicate.
  - `is_signed_by(ev, trusted_key_or_identity)`.
  - `matches_version(ev, required_version)`.
  Predicate names and polarity must be explicit: a claim like “no high-severity vulnerabilities” must fail when a confirmed high-severity vulnerability exists.
- Define each predicate's evidence requirements and behavior for missing, stale, unauthenticated, contradictory, and inapplicable evidence.
- Apply the global `PASS` / `FAIL` / `UNKNOWN` semantics.
- Produce a structured trace explaining which evidence and predicate produced each result.
- Add memoization only after correctness is established.

**Memoization key**
- Include a canonical fingerprint of the complete claim specification, predicate identifiers and parameters, dependency closure, relevant evidence IDs and hashes/versions, verification and freshness states, trust-policy configuration/version, evaluation time or relevant validity inputs, and engine/rule version.
- Ensure any verdict-affecting change invalidates/rekeys the cache.
- Do not rely on `frozenset(graph.closure(node))` alone.

**Files**
- `app/engine.py`
- `tests/test_engine.py`

**Tests**
- PASS with all required evidence valid.
- FAIL when evidence proves a required condition false.
- UNKNOWN for missing or insufficient evidence.
- Contradictory evidence.
- Stale evidence and re-evaluation.
- Diamond graph/shared-dependency memoization.
- Different claims/predicates over the same graph do not incorrectly share cached results.
- Evidence hash/version update forces recomputation.
- Trust-policy or predicate-parameter change forces recomputation.
- Identical complete inputs produce identical verdict and trace.

**Dependencies**
- Phases 1 and 2.

**Exit criteria**
- Engine tests pass.
- The core function has no FastAPI/database side effects.
- Identical complete inputs produce identical results.

### Phase 4 — Cross-Evidence Consistency Checker

**Goal:** Detect explicit contradictions among evidence items.

**Tasks**
- Create `app/consistency.py`.
- Define a `Conflict` model with ID, type, description, affected evidence IDs, and affected fields.
- Implement `check_consistency(evidence_list) -> list[Conflict]`.
- Start with explicit rules:
  - Hash mismatch for evidence expected to describe the same artifact/version.
  - Incompatible version assertions/ranges.
  - Provenance subject mismatch against the target artifact.
  - Material timestamp/validity disagreement.
- Compare evidence only when artifact identity, version, and context make the comparison meaningful.
- Report conflicts rather than silently choosing an authoritative source.
- Keep authority resolution in explicit trust/policy rules, not implicit source ranking.

**Files**
- `app/consistency.py`
- `tests/test_consistency.py`

**Tests**
- Each supported conflict type.
- Clean evidence set returns no conflicts.
- Unrelated artifacts are not compared incorrectly.
- Evidence from different issuers is not automatically treated as a conflict without a substantive disagreement.

**Dependencies**
- Phase 1; engine trace integration may follow Phase 3.

**Exit criteria**
- Conflicts are deterministic, structured, and tested.
- No implicit “most trusted” source selection.

### Phase 5 — Temporal Validity and Revalidation

**Goal:** Detect stale/changed evidence and re-evaluate only affected claims.

**Tasks**
- Create `app/validity.py`.
- Support optional `valid_from` and `valid_until` timestamps in a consistent timezone-aware format.
- Implement `is_stale(evidence, now)`.
- Implement `affected_claims(claims, stale_evidence_ids)`.
- Track evidence changes by ID plus version/hash.
- Re-evaluate claims affected by expired, changed, or invalidated evidence.
- Ensure the cache key or invalidation mechanism accounts for freshness and evaluation time.
- If required evidence is stale and no sufficient current evidence remains, the result must be `UNKNOWN`, not PASS.

**Files**
- `app/validity.py`
- `tests/test_validity.py`

**Tests**
- Fresh evidence.
- Expired evidence.
- Not-yet-valid evidence.
- Missing validity metadata where validity is required.
- Changed evidence triggers re-evaluation.
- Fresh replacement evidence restores a determinable verdict.

**Dependencies**
- Phases 1 and 3; integrate consistency results as appropriate.

**Exit criteria**
- Temporal checks are deterministic for a supplied evaluation time.
- Affected-claim selection and re-evaluation work.

### Phase 6 — Persistent Storage Abstraction

**Goal:** Persist evidence, claims, verdicts, and conflicts behind a stable storage interface.

**Tasks**
- Create `app/storage.py`.
- Use SQLAlchemy 2.0 with SQLite initially.
- Provide repository-style interfaces for:
  - Evidence: add, get, list, update, delete.
  - Claims: add, get by ID, list.
  - Verdict history: record and retrieve.
  - Conflicts: record and retrieve.
  - Dependency relationships as needed.
- Include project/artifact identifiers where needed for isolation.
- Store evidence hashes, verification status, timestamps, and policy/engine versions needed for auditability.
- Use schema migrations when schema evolution warrants it; document the migration path to PostgreSQL.
- Keep business logic out of database-specific code.

**Files**
- `app/storage.py`
- Storage model/module files as needed.
- `tests/test_storage.py`
- Optional `alembic.ini` and migrations.

**Tests**
- CRUD operations.
- Persistence across store/application restart.
- Duplicate IDs and invalid references.
- Project scoping where applicable.
- Verdict history retrieval.
- Schema/migration smoke tests if migrations are introduced.

**Dependencies**
- Phase 1; coordinate with Phases 3 and 5.

**Exit criteria**
- SQLite persistence works.
- Engine/API can use the storage abstraction without depending on SQLite implementation details.

### Phase 7 — Evidence-Source Ingestion and Verification

**Goal:** Ingest real supply-chain evidence while keeping parsing separate from authenticity and trust evaluation.

**Common rules**
- Validate normalized records against the Evidence model.
- Distinguish parsing, content integrity, cryptographic authenticity, artifact binding, and trust-policy acceptance.
- Do not mark evidence as verified merely because a parser succeeded.
- Do not silently discard invalid records without a structured error/log entry.
- Make missing, invalid, and unsupported evidence distinguishable.
- Use safe subprocess invocation, timeouts, and clear errors for external tools.
- Tests may mock external tools for unit tests, but at least one integration path must exercise real tooling where feasible.

#### 7a. SBOM ingestion — `app/ingest/sbom.py`

**Tasks**
- Parse CycloneDX JSON and SPDX JSON.
- Extract components, package identifiers, versions, and relevant artifact metadata.
- Normalize into `Evidence` records with `type="SBOM"`.
- Calculate SHA-256 of the exact input bytes and store it as `srcHash`.
- Bind the SBOM to its declared artifact/subject only when supported by the input and validation process.
- Treat the calculated hash as an identifier for the received bytes, not proof that the SBOM is authentic.
- If an expected hash or authenticated reference is available, compare it and record the outcome.

#### 7b. Vulnerability ingestion — `app/ingest/vuln.py`

**Tasks**
- Parse supported OSV JSON/OSV-Scanner output.
- Normalize vulnerability IDs, affected package identifiers, affected version ranges, severity data when present, and source metadata.
- Use `type="VULN"` and bind each record to the affected package/artifact and version context.
- Do not invent severity when the source omits it; represent unavailable severity as unknown.
- Preserve source timestamps/versions when available.

#### 7c. Cosign signature verification — `app/ingest/sig.py`

**Tasks**
- Invoke `cosign verify <image_ref>` safely with argument arrays, controlled timeout, and captured exit status/output.
- On success, parse verification output and extract the verified artifact digest and signer/signature identity metadata supported by the output.
- Bind the resulting evidence to the verified digest, not merely a mutable image tag.
- Check the signer identity and applicable issuer/key constraints against explicit trust policy.
- Record separate signature verification and trust-policy outcomes.
- If verification fails or no acceptable signature is present, return a clear failure/error result; never create verified-signature evidence.
- Add a supported verification path for the intended signature mode and document its assumptions.

#### 7d. in-toto/SLSA provenance — `app/ingest/prov.py`

**Tasks**
- Parse the supported in-toto/SLSA attestation or bundle format.
- Verify signatures/proofs using supported libraries and documented trust roots/identity policy.
- Validate the attestation subject against the exact artifact digest being evaluated.
- Extract builder identity, relevant predicate/build metadata, attestation hash, and SLSA fields only when actually present and validated.
- Do not infer a SLSA level from incomplete data.
- Keep parsing, cryptographic verification, subject binding, and trust-policy evaluation as separate results.

#### Tests and deliverables for Phase 7

**Files**
- `app/ingest/__init__.py`
- `app/ingest/sbom.py`
- `app/ingest/vuln.py`
- `app/ingest/sig.py`
- `app/ingest/prov.py`
- `tests/test_ingest.py`

**Tests**
- Valid CycloneDX and SPDX SBOM.
- Malformed SBOM.
- SBOM whose calculated hash differs from a trusted expected hash.
- Valid and malformed OSV data.
- OSV records with missing severity/version information.
- Valid Cosign verification.
- Invalid signature, missing signature, wrong digest, and untrusted signer.
- Valid provenance, invalid proof/signature, mismatched subject, unsupported format, and missing bundle.
- Missing files/inputs produce explicit errors.
- Ensure parsing-only evidence is never marked cryptographically verified.

**Dependencies**
- Phase 1; integrate with storage and engine as appropriate.
- Tooling: Syft, OSV-Scanner/OSV data, Cosign CLI, and supported in-toto/SLSA libraries.

**Exit criteria**
- All ingestion tests pass.
- At least one end-to-end path uses real tool output.
- No placeholder or always-successful verification behavior remains.

### Phase 8 — Verdict and Explanation API

**Goal:** Expose evaluation results and structured explanations through FastAPI.

**Tasks**
- Add `POST /evaluate`.
- Add `GET /explain/{claim_id}`.
- Add or update Pydantic request/response schemas in `app/schemas.py`.
- Load relevant claims, graph data, evidence, and policy from the configured services/storage.
- Return verdict, structured trace, conflict information where relevant, and evaluation metadata.
- The API must never translate UNKNOWN into PASS.
- Keep the API independent of the dashboard; any client consumes the API.
- Keep natural-language/AI explanations optional and strictly advisory. The structured backend trace remains authoritative.

**Files**
- `main.py`
- `app/schemas.py`
- `tests/test_evaluate.py`

**Tests**
- PASS, FAIL, and UNKNOWN responses.
- Malformed request.
- Missing claim/evidence.
- Trace schema.
- Stale and contradictory evidence.
- Policy configuration behavior.
- API never returns a successful security verdict for UNKNOWN.

**Dependencies**
- Phases 3 and 6; integrate 4 and 5 outputs.

**Exit criteria**
- API routes are documented and integration tests pass.
- The API can be called by CI and the later dashboard.

### Phase 9 — Application Security

**Goal:** Add practical application-security controls before production-like deployment.

**Tasks**
- Add authentication and authorization appropriate to the intended deployment.
- If JWT is enabled, use environment-driven secrets, clear token validation, and roles such as project member/admin.
- Enforce project/user isolation in storage and every relevant query.
- Validate inputs with Pydantic.
- Add safe exception handlers; expose generic client errors while logging actionable internal context.
- Add structured audit records for evaluations: claim, project, verdict, policy/engine version, timestamp, and actor when authenticated.
- Read secrets from environment variables; provide `.env.example` with placeholders only.
- Pin/constrain dependencies and run `pip-audit` in CI.
- Run the container as a non-root user.
- Avoid claiming authentication is enabled if it is merely optional or disabled in the running configuration; document the active mode.

**Files**
- `app/security.py`
- `app/audit.py`
- `.env.example`
- `tests/test_security.py`
- Updates to `main.py`, CI, and container configuration.

**Tests**
- Authentication success/failure.
- Authorization and project isolation.
- Input validation and safe errors.
- Audit event creation.
- Secret configuration missing/invalid.
- Dependency audit workflow runs.

**Dependencies**
- Phases 6 and 8.

**Exit criteria**
- Security tests pass.
- Secrets are not committed.
- Data isolation is tested.
- The deployed configuration is documented.

### Phase 10 — Configurable CI/CD Policy Gate

**Goal:** Map verdicts to explicit deployment actions without treating UNKNOWN as valid by default.

**Tasks**
- Create `app/policy.py` with a `PolicyEngine`.
- Map `PASS`, `FAIL`, and `UNKNOWN` to `ALLOW`, `BLOCK`, or `RETRY`.
- Provide a default policy such as PASS → ALLOW, FAIL → BLOCK, UNKNOWN → BLOCK.
- Support validated per-project overrides.
- Use a YAML configuration file or environment-driven policy configuration.
- Ensure the policy version/configuration is included in evaluation records and cache keys when it affects the verdict/action.
- Provide a CI example that invokes ClaimMesh and fails the job when the policy returns BLOCK.
- Do not make a test's incidental UNKNOWN result the only integration design; test the actual CLI/API-to-policy flow.
- Document behavior and override risks.

**Files**
- `app/policy.py`
- `policy.yaml`
- `tests/test_policy.py`
- CI workflow and README updates.
- A CLI/script or documented API invocation for pipeline use.

**Tests**
- Default mapping for all verdicts.
- Custom mapping and per-project overrides.
- Invalid policy configuration.
- End-to-end pipeline blocks on configured UNKNOWN.
- Retry action has bounded/documented behavior and cannot become an infinite loop.

**Dependencies**
- Phases 8 and 9.

**Exit criteria**
- Policy is explicit, validated, testable, and used by a CI example.
- UNKNOWN never silently becomes ALLOW.

### Phase 11 — Containerized and Reproducible Deployment

**Goal:** Run ClaimMesh reproducibly on a developer machine or host.

**Tasks**
- Add a multi-stage Dockerfile where practical.
- Run the application as a non-root user.
- Add `docker-compose.yml` for the app and SQLite volume/configuration.
- Add a container health check.
- Emit logs to stderr/stdout in structured JSON or a documented structured format.
- Document all environment variables in `.env.example`.
- Document build, run, upgrade, backup, and troubleshooting basics appropriate to the prototype.
- Ensure runtime configuration does not include real secrets in the image or repository.

**Files**
- `Dockerfile`
- `docker-compose.yml`
- `.env.example`
- Updated README.
- Container smoke tests or CI job as appropriate.

**Tests**
- Docker image builds.
- Container starts.
- Health endpoint responds successfully.
- SQLite data persists through a container restart when configured to use a volume.
- Missing required configuration fails clearly and safely.

**Dependencies**
- Phases 6 and 9.

**Exit criteria**
- `docker-compose up` starts the app.
- Health check succeeds.
- Deployment steps work from a clean checkout.

### Phase 12 — End-to-End Evaluation and Research Benchmarks

**Goal:** Validate the full pipeline with real project evidence and reproducible measurements.

**Tasks**
- Select a small, documented set of real software targets, such as a Python package, Go module, or container image.
- Generate SBOMs using Syft and collect vulnerability data with OSV-Scanner or supported OSV data.
- Use signed images/provenance when available; clearly label test fixtures and any synthetic signature/provenance scenarios.
- Ingest evidence, construct dependency graphs, evaluate claims, run consistency checks, and record verdicts/traces.
- Include claims such as “no known high-severity vulnerabilities under the selected data snapshot” with explicit scope and timestamp.
- Benchmark graph sizes of 5, 15, and 30 nodes (and larger only if practical).
- Measure composition runtime, cache hit/recompute behavior, consistency-check latency, and storage read/write time.
- Record false positives/false negatives only when a defensible ground-truth method exists; otherwise report observed mismatches and limitations.
- Generate CSV data and plots plus a Markdown evaluation report.
- Separate synthetic benchmarks from real-project results. Do not present a small synthetic test as production-scale validation.

**Files**
- `benchmarks/`
- `scripts/run_benchmarks.py`
- `evaluation_report.md`

**Tests**
- Reproducible benchmark command completes.
- End-to-end test covers evidence ingestion → storage → evaluation → API/policy result.
- Report generation works.
- Inputs, tool versions, data snapshot dates, and environment are recorded.

**Dependencies**
- All prior backend phases, especially 3–11.

**Exit criteria**
- At least one real-project end-to-end run succeeds.
- Benchmarks and report are produced.
- Limitations and evaluation methodology are documented.

### Phase 13 — Dashboard (Level 2 Deliverable)

**Goal:** Provide a functional UI after the backend API and core integrations stabilize.

**Tasks**
- Build with React + TypeScript.
- Use Cytoscape.js for dependency-graph visualization.
- Consume ClaimMesh API endpoints; do not duplicate security logic in the frontend.
- Display:
  - Projects and artifacts.
  - Dependency graphs.
  - Evidence inventory and verification/freshness status.
  - Claim verdicts and expandable structured traces.
  - Consistency conflicts.
  - Stale-evidence and revalidation history.
  - CI/CD results and configured policy actions.
- Show UNKNOWN distinctly; never style or label it as PASS.
- Make errors, loading states, and empty data clear.
- AI analyst is optional. If later added, mark its output as advisory and keep it outside the verdict/policy path.

**Files**
- `frontend/` React application.
- `frontend/package.json`
- API client wrapper and UI components.
- Frontend tests.

**Tests**
- Components render correctly for PASS, FAIL, UNKNOWN, missing evidence, and conflicts.
- API client handles errors.
- Graph and trace views use backend-provided data.
- No frontend code makes security verdicts or deployment-policy decisions.

**Dependencies**
- Stable Phase 8 API and relevant Phase 4/5/10 outputs.

**Exit criteria**
- UI runs locally (for example, on port 3000).
- It can display a sample project's graph, evidence, verdicts, traces, and policy results using the backend API.
- Dashboard is treated as part of the Level 2 target, not a prerequisite for starting backend work.

---

## 6. Cross-Phase Dependency Map

| Phase | Depends on |
|---|---|
| 0 | None |
| 1 | 0 |
| 2 | 1 |
| 3 | 1, 2 |
| 4 | 1, 3 for full integration |
| 5 | 1, 3, 4 as integrated |
| 6 | 1; coordinate with 3 and 5 |
| 7 | 1; integrate with 6 and 3 |
| 8 | 3, 6; integrate 4 and 5 |
| 9 | 6, 8 |
| 10 | 8, 9 |
| 11 | 6, 9 |
| 12 | All backend phases, especially 3–11 |
| 13 | Stable API and core integrations; build after backend stabilizes |

Phases can be developed in parallel only when interfaces are agreed and tests can run independently. Merge only after integration checks pass.

---

## 7. Definition of Done for Each Phase

Before marking a phase complete:

1. Implementation matches its stated scope.
2. Unit tests pass locally.
3. Integration tests pass where relevant.
4. CI is green.
5. No placeholder verification is represented as real verification.
6. Errors and unsupported inputs are handled explicitly.
7. README/docs are updated where behavior or setup changed.
8. Changes are committed on a branch and reviewed before merging.
9. The next phase is not started until the current phase's exit criteria are met, unless an explicitly documented parallel task has stable interfaces.

Do not pursue 100% coverage as a substitute for meaningful tests. Aim for strong coverage of decision logic, edge cases, and security-sensitive paths.

---

## 8. Key Risks and Mitigations

| Risk | Mitigation |
|---|---|
| Schema drift between evidence and parsers | Canonical Pydantic models and parser-specific tests |
| Parsing mistaken for authenticity | Separate parsing, integrity, signature/proof, artifact binding, and trust status |
| Evidence for the wrong artifact | Bind signatures/provenance/SBOM claims to exact artifact identity and digest where supported |
| Stale cache returns old verdict | Complete cache fingerprint plus evidence-change and policy-change tests |
| Missing evidence becomes PASS | Explicit three-valued semantics and tests |
| Conflicting evidence silently resolved | Report conflicts; only resolve via explicit documented policy |
| Mutable image tag used as identity | Record and evaluate immutable image digest |
| External command injection/timeouts | Argument arrays, no shell interpolation, timeout, and clear error handling |
| Security data leaks across projects | Project-scoped authorization and storage-query tests |
| Works only on synthetic evidence | End-to-end tests using real tool output and documented limitations |
| Dashboard duplicates decision logic | Backend-only verdicts and API-driven frontend |
| Scope expands indefinitely | Keep advanced infrastructure and AI optional; complete the agreed phases first |

---

## 9. First Implementation Task — Phase 0

Start with Phase 0 only.

1. Create `app/`, `tests/`, `scripts/`, and `.github/workflows/`.
2. Implement `main.py` with `/health` and `/info`.
3. Add `tests/test_main.py`.
4. Add the required dependencies to `requirements.txt`.
5. Add a minimal `README.md`.
6. Add `.github/workflows/ci.yml` to install dependencies and run pytest.
7. Run the tests locally.
8. Commit and push the changes.
9. Confirm GitHub Actions passes from the repository.
10. Stop and review before beginning Phase 1.

**Phase 0 is complete only when a clean checkout can install, run, test, and pass CI.**

---

## 10. Final Product Acceptance Checklist

- [ ] Models validate evidence, claims, predicates, verdicts, conflicts, and traces.
- [ ] Dependency graph closure and cycle rejection work.
- [ ] Engine is deterministic and has correct PASS/FAIL/UNKNOWN semantics.
- [ ] Memoization accounts for all verdict-affecting inputs and re-evaluates after changes.
- [ ] Consistency checker detects supported contradictions without silently selecting authority.
- [ ] Temporal validity and targeted revalidation work.
- [ ] Evidence, claims, verdicts, and conflicts persist.
- [ ] CycloneDX/SPDX SBOM and OSV ingestion work on supported real data.
- [ ] Cosign verification checks actual signatures, digest binding, signer identity, and trust policy.
- [ ] in-toto/SLSA provenance validation checks supported proof/signature, subject binding, and trust requirements.
- [ ] Missing, malformed, invalid, stale, and untrusted evidence are handled explicitly.
- [ ] API exposes verdicts and structured traces.
- [ ] CI/CD policy maps verdicts to actions and does not silently allow UNKNOWN.
- [ ] Security controls, audit logging, secret management, and project isolation are tested.
- [ ] Docker deployment is reproducible and health checks pass.
- [ ] Real-project end-to-end run and benchmark report are reproducible.
- [ ] Dashboard displays backend results without making security decisions.
- [ ] Documentation explains scope, assumptions, limitations, and how to run the system.

---

## 11. Scope Guardrails

For the initial Level 2 delivery:

- Keep the core deterministic and explainable.
- Do not make AI a dependency for security decisions.
- Do not introduce complex infrastructure without evidence it is needed.
- Treat external-tool integration as incomplete until its verification path and failure cases are tested.
- Clearly distinguish what has been implemented, what has been mocked in tests, and what has been validated against real tool output.
- Do not claim production-scale reliability based only on unit tests or synthetic benchmarks.

**Implementation instruction:** Follow the phases in order, implement one bounded task at a time, run tests, report changed files and test results, and wait for approval at each phase boundary. Begin with Phase 0; do not implement later phases in the same task.
