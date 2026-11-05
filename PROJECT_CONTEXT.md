# ClaimMesh — Project Context

## 1. Project purpose
ClaimMesh is a software supply-chain evidence composition and verification system. It evaluates whether a specified security claim about a software artifact is supported by evidence across its in-scope dependency closure. It is a final-year project based on a related Systematization of Knowledge (SoK) paper. Keep implementation and documentation aligned with the architecture below. Do not claim novelty, production readiness, or capabilities that have not been demonstrated.

## 2. Core problem
Software supply-chain evidence is heterogeneous and often evaluated in isolation. ClaimMesh aims to compose evidence into dependency-aware claims, detect contradictions across evidence sources, and identify when claims need reassessment because evidence changes or becomes stale. The challenge is not merely storing a dependency graph; it is evaluating claims over relevant dependencies, checking consistency, and maintaining validity as evidence changes.

## 3. Target architecture
Follow this baseline:
1. Evidence sources — SBOM generators, provenance/attestation tools, signature/transparency-log validation, vulnerability feeds, and runtime monitors where supported.
2. Evidence ingestion and normalization.
3. Evidence store / claim-evidence index.
4. Dependency closure graph builder.
5. Claim Specification Language (CSL) defining scope, required predicates, consistency constraints, and revalidation requirements.
6. Composition Engine evaluating claims over the in-scope dependency closure.
7. Cross-Evidence Consistency Checker detecting defined contradictions.
8. Temporal Validity Monitor identifying stale, expired, withdrawn, revoked, or superseded evidence where supported and triggering reassessment.
9. Verdict and Explanation Layer returning deterministic verdicts and traceable reasons.
10. Deployment / CI/CD Gate applying explicit policy to deterministic results.
11. Feedback loop: evidence changes can trigger revalidation of affected claims.
12. Optional AI Analyst explaining structured results and suggesting remediation. This is a proposed extension; the current paper does not explicitly define a separate AI component.

## 4. Evidence model
The paper proposes an Evidence Object of the general form:
`E = <id, type, subject, issuer, assertions, validity, srcHash>`
Implement a typed model for these fields. Add fields only when needed and document why. Preserve evidence origin and relevant metadata.

Parsing evidence does not establish authenticity. Keep parsing, integrity checks, signature verification, issuer trust, and policy evaluation distinct.

## 5. Claims and verdict semantics
A claim specification should express the target artifact and scope, required evidence predicates, consistency constraints, and validity/revalidation requirements.

Use explicit verdicts:
- `PASS`: all required conditions are satisfied by sufficient acceptable evidence.
- `FAIL`: evidence establishes that a required condition is violated according to configured rules.
- `UNKNOWN`: evidence is missing, insufficient, unsupported, or cannot establish a reliable result.

Never silently treat missing or unverifiable evidence as passing. Define explicit CI/CD policy for `UNKNOWN`.

## 6. Composition engine requirements
The deterministic engine should:
1. Accept a claim specification.
2. Identify the target artifact.
3. Build or retrieve the relevant dependency closure.
4. Retrieve relevant evidence for nodes and edges.
5. Evaluate predicates according to explicit rules.
6. Combine dependency results according to documented claim semantics.
7. Use memoization where appropriate to avoid repeated evaluation of shared dependencies in diamond-shaped graphs.
8. Produce a structured trace explaining the result and referencing the evidence and rules used.

Keep evaluation deterministic and testable. An LLM must not decide or override security verdicts.

## 7. Cross-evidence consistency
Start with explicit conflict types such as artifact identity/version mismatch, hash mismatch, component-list disagreement, provenance subject mismatch, and relevant timestamp/validity disagreement. Report the evidence and fields involved. A contradiction does not automatically establish which source is authoritative; source precedence must be explicit policy if implemented.

## 8. Temporal validity and revalidation
Track validity information supported by formats and data sources. When evidence expires or changes, identify affected claims and reassess them. Record why revalidation was triggered and how results changed. Do not claim complete revocation, withdrawal, or supersession handling until implemented and tested.

## 9. Cyclic dependency graphs
The current paper prototype evaluates acyclic dependency graphs and rejects cycles before evaluation. Preserve this behavior initially. Cycle-aware evaluation is a future extension and must not be represented as already supported. If added later, define cycle semantics first, detect strongly connected components, ensure termination, and test propagation and edge cases.

## 10. Proposed technology stack
This is a proposal, not an immutable requirement:
- Python, FastAPI, Pydantic, NetworkX, pytest
- SQLite initially; consider PostgreSQL when justified
- Syft for SBOM generation
- CycloneDX and SPDX support
- OSV-Scanner / OSV data for vulnerability evidence
- Cosign for supported signature verification
- in-toto / SLSA-compatible attestations for provenance
- GitHub Actions for CI/CD
- Docker for reproducible packaging
- React + TypeScript + Cytoscape.js for a later dashboard
- Optional provider-independent LLM integration for advisory explanations

Do not add Neo4j, Kubernetes, a task queue, or other infrastructure unless a demonstrated requirement justifies the complexity.

## 11. Suggested implementation sequence
1. Repository setup, configuration, health endpoint, and tests.
2. Evidence Object, claim specification, and verdict models.
3. Dependency graph and dependency closure; detect and reject cycles initially.
4. SBOM ingestion and normalization.
5. Deterministic claim composition engine with memoization and trace output.
6. Cross-evidence consistency checker.
7. Temporal validity and targeted revalidation.
8. Structured verdict/explanation API.
9. Incremental integration of vulnerability, signature, and provenance evidence.
10. CI/CD gate with explicit handling of `PASS`, `FAIL`, and `UNKNOWN`.
11. Optional cycle-aware evaluation extension.
12. Optional AI analyst.
13. Dashboard.
14. Reproducible evaluation and documentation.

Complete and test each stage before moving to the next. Do not build the dashboard or AI first.

## 12. Testing and evaluation
Use pytest and controlled fixtures with known expected results. Evaluate model validation, claim parsing, dependency closure correctness, composition correctness for direct/transitive/shared dependencies, memoized versus non-memoized evaluation, missing and contradictory evidence, expiry/change and revalidation propagation, initial cycle rejection, CI/CD decisions for PASS/FAIL/UNKNOWN, and performance across increasing graph sizes. If AI is implemented, assess explanation fidelity.

Report test environment, graph sizes, methodology, and limitations. Treat preliminary synthetic benchmarks as preliminary, not proof of production-scale performance.

## 13. AI design constraints
AI is advisory only. It may explain failure paths, summarize conflicts, and suggest remediation using structured engine output and relevant evidence excerpts. It must distinguish facts from suggestions, express uncertainty, not invent evidence, not change verdicts, and not bypass the deployment gate. Evaluate explanations against the deterministic trace. If AI becomes part of the formal research contribution, update the architecture, methodology, and evaluation.

## 14. Research and patent caution
- Do not claim ClaimMesh or any mechanism is novel or patentable without prior-art research and professional assessment.
- Do not invent novelty claims in code, README files, reports, or papers.
- Keep dated records of design decisions and development milestones.
- The SoK paper and intended patent concept may overlap architecturally. Do not assume they are independent or that the paper has no effect on patent rights.
- Before sending detailed potentially novel mechanisms to third-party services, check privacy, retention, and provider-routing policies for the complete AI pipeline.
- Never place secrets, credentials, private keys, or tokens in prompts or repository files.

## 15. Coding-agent instructions
1. Inspect existing files before changing them.
2. Follow the architecture and implementation order above.
3. Make small, reviewable changes.
4. Briefly explain planned changes before substantial edits.
5. Write or update tests for each behavior.
6. Run tests and report actual results; never claim tests passed without running them.
7. Do not silently add major dependencies or change architecture.
8. Document assumptions about evidence schemas and claim semantics.
9. Keep deterministic verification separate from AI explanations.
10. Do not hardcode secrets.
11. Update documentation when behavior changes.
12. Ask before consequential decisions when requirements are ambiguous.
13. Prefer maintainable code over premature optimization.
14. Work on the current phase only; do not implement every phase at once.

## 16. First task for the coding agent
Start with Phase 0 only:
- Inspect the repository state.
- If empty, create the Python project structure.
- Add FastAPI startup and a simple health endpoint.
- Add pytest coverage for the health endpoint.
- Add dependency declarations and a concise README with setup/test commands.
- Run tests and report the exact outcome.
- Do not implement evidence models or the composition engine until setup is reviewed.

## 17. Initial project status
At the time this context file was created, setup had been proposed but was not confirmed as completed. Do not assume the environment, repository, dependencies, or files already exist. Inspect before acting.
