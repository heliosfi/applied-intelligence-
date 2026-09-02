# Applied Evidence / Applied Knowledge

A deterministic, evidence-centered architecture for ordered execution, cryptographic auditability, reproducible verification, performance governance, and bounded defect routing.

## Status and evidence boundary

This repository preserves the current architecture and evolutionary-stage record. Statements below describe the reported design and development milestones supplied for this package. A README is not, by itself, proof of production deployment, independent security validation, benchmark reproducibility, secret provisioning, or an active Linear integration. Those claims become repository-verified only when the corresponding source, tests, workflows, artifacts, and successful run evidence are committed and reviewable here.

## Master architecture: Applied Evidence Pipeline

The Applied Evidence Pipeline is designed to:

- enforce deterministic transaction ordering;
- reject illegal state transitions;
- produce consistently serialized payloads;
- support HMAC-SHA256 and RSA-PSS/SHA-256 signing;
- verify individual and Merkle-batched audit envelopes;
- detect performance regressions through CI thresholds; and
- route verified regression evidence into Linear when explicitly configured and authorized.

### Core technical stack

| Area | Technology |
|---|---|
| Language and runtime | Python 3.11 |
| Cryptography | RSA-PSS with SHA-256, HMAC-SHA256, SHA-256 hashing, binary Merkle trees |
| CI governance | GitHub Actions, commit-signature checks, audit verification, benchmark thresholds, automated PR reporting |
| Defect routing | Linear GraphQL API |
| Metrics and visualization | JSON benchmark artifacts and matplotlib trend rendering |

Cryptographic signatures support integrity and origin verification when keys are properly generated, protected, attributed, rotated, and independently verified. They do not establish non-repudiation merely by existing.

## Evolutionary stages

### Stage 1 — Core state machine and cryptographic engine

#### Deterministic transition rules

The reported `OrderStateMachine` permits only sequential progression:

```text
scheduled → dispatched → in-progress → completed
```

Illegal or out-of-order transitions are rejected using HTTP 409-style conflict semantics.

#### Cryptographic signer

The reported `CryptographicSigner` supports:

- HMAC-SHA256;
- asymmetric RSA-PSS signatures using SHA-256; and
- deterministic JSON dictionary ordering through `sort_keys=True` to improve payload-byte consistency.

Canonical serialization must also define encoding, separators, Unicode handling, numeric representation, and excluded fields before cross-runtime byte parity can be treated as established.

#### Multi-symbol parity

Parallel execution was reported across:

- `HELIOS-USD`;
- `SELENE-ETH`; and
- `AETHER-BTC`.

The supplied development record reports 100% SHA-256 payload-hash agreement across those runs with zero observed drift. Reproducible commands, raw outputs, environment details, and committed artifacts are required before this result is independently verifiable from this repository.

### Stage 2 — Continuous governance and CI enforcement

#### Signed audit CI

The proposed `.github/workflows/signed-audit-ci.yml` workflow combines:

- GPG/SSH commit-signature validation;
- audit-envelope verification;
- benchmark execution;
- regression-threshold enforcement; and
- bounded Linear defect routing when credentials and authority are present.

Repository rulesets or branch protection remain necessary if signature checks are intended to block unverified changes rather than merely report them.

#### Independent audit verification

The reported `verify_audit_log.py` parses exported audit packages and independently re-evaluates supported signatures and envelope integrity outside the signing path.

### Stage 3 — Production security and secret management

#### Environment-based secret loading

The reported signer loads:

- `RSA_PRIVATE_KEY_PEM`; and
- `HMAC_SECRET_KEY`

from environment or vault-backed variables.

Any runtime-generated ephemeral fallback should be restricted to explicit development or test mode. Production execution should fail closed when required signing material is missing, malformed, or unauthorized.

#### Key-generation utility

The reported `generate_keys.py` creates 2048-bit RSA key pairs formatted for controlled injection into GitHub Secrets or a secrets manager such as HashiCorp Vault.

Generated private keys must never be committed, logged, placed in build artifacts, or exposed in CI output.

### Stage 4 — Benchmarking and regression monitoring

#### Concurrent benchmarking

The reported `benchmark_throughput.py` supports up to 100 parallel workers and measures:

- throughput in operations per second;
- mean latency; and
- concurrency and thread overhead.

#### Automated regression gates

The reported command-line controls include:

- `--min-throughput`; and
- `--max-regression-pct`.

CI is designed to fail when results fall below an approved operational floor or exceed the allowed regression percentage.

#### Historical metric persistence

The reported pipeline preserves `benchmark_results.json` and uses `render_benchmark_trends.py` to visualize throughput and latency trends with matplotlib.

Valid trend comparisons require a defined baseline, consistent hardware or normalized environments, warm-up policy, sample size, variance reporting, and artifact provenance.

### Stage 5 — High-scale optimization and Linear integration

#### Merkle batch signing

The reported `merkle_batch_signer.py` groups payloads into a binary Merkle tree and signs the root once with RSA-PSS. This can reduce asymmetric signing work from up to `N` signatures to one root signature per batch, while each payload retains a verifiable inclusion path.

This optimization changes the verification model: proof integrity depends on leaf construction, sibling ordering, tree-shape rules, odd-leaf handling, root serialization, and secure root-signature verification.

#### Dual-schema audit verification

The reported verifier auto-detects and validates:

1. standard individually signed audit envelopes; and
2. Merkle inclusion proofs anchored to a signed root.

Schema detection must be explicit and fail closed for unknown, ambiguous, incomplete, or malformed envelope versions.

#### Linear defect automation

The reported `linear_integration.py` and `create_linear_regression_issue.py` create Linear defect tickets when CI confirms a qualifying performance regression.

Issue creation is an external side effect and should require:

- configured credentials;
- an explicit team and project destination;
- deduplication or idempotency controls;
- bounded evidence attachments;
- clear failure handling; and
- no inference of deployment or remediation authority.

## Core artifact map

```text
.
├── .github/
│   └── workflows/
│       └── signed-audit-ci.yml
├── benchmark_results.json
├── create_linear_regression_issue.py
├── generate_keys.py
├── linear_integration.py
├── merkle_batch_signer.py
├── order_execution_audit.json
├── render_benchmark_trends.py
├── signed_audit_suite.py
└── verify_audit_log.py
```

| Artifact | Responsibility |
|---|---|
| `.github/workflows/signed-audit-ci.yml` | Unified signature, audit, benchmark, and bounded defect-routing workflow |
| `benchmark_results.json` | Per-commit benchmark evidence artifact |
| `create_linear_regression_issue.py` | Regression-to-Linear orchestration wrapper |
| `generate_keys.py` | RSA key-pair generation utility |
| `linear_integration.py` | Linear GraphQL client |
| `merkle_batch_signer.py` | Merkle-tree construction, root signing, and inclusion-proof generation |
| `order_execution_audit.json` | Signed audit-envelope example or evidence artifact |
| `render_benchmark_trends.py` | Historical throughput and latency visualization |
| `signed_audit_suite.py` | Core state machine and cryptographic signing logic |
| `verify_audit_log.py` | Standalone verification for individual and Merkle audit formats |

## Verification progression

The next evidence-bounded progression is:

1. commit the referenced artifacts without private keys or live credentials;
2. add deterministic unit and negative-path tests;
3. publish exact local reproduction commands;
4. run CI and preserve immutable run evidence;
5. compare the documented artifact map with the committed tree;
6. classify every milestone as **VERIFIED**, **PARTIAL**, **HOLD**, or **NOT PRESENT**; and
7. request independent technical and security review before any production claim.

## Governance posture

```text
ARCHITECTURE != DEPLOYMENT
DOCUMENTATION != EXECUTION EVIDENCE
SIGNATURE PRESENT != SIGNER AUTHORITY
BENCHMARK RESULT != PRODUCTION CAPACITY
LINEAR ISSUE CREATION != REMEDIATION AUTHORITY
```

The architecture is intended to preserve deterministic behavior, evidence integrity, bounded automation, and explicit authority. Unknown, unverifiable, or unauthorized states should fail closed.
