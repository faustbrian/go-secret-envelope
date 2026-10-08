# Security

## Threat model version

- Model: `SECRET-ENVELOPE-THREAT-MODEL-v2`
- Reviewed: 2026-10-05
- Owner: secret-envelope maintainers

Review this model when an algorithm, envelope version, provider interface,
input bound, error contract, or trust boundary changes, or when a security
incident contradicts an assumption below.

## Assets and security objectives

The protected assets are plaintext payloads, plaintext data keys, keyring
wrapping keys, KMS authorization, authenticated context, persisted envelope
integrity, and externally signed statement integrity. The package aims to keep
payload and key material confidential, make any change to an envelope or its
binding context fail authentication, and make signature verification fail
closed unless KMS confirms the exact key, raw message, signature, and selected
algorithm.

Deletion, rollback, replay, availability, signer authorization, and retention
remain application concerns because this stateless module owns no durable
clock, sequence, identity, policy, or storage.

## Trust boundaries and attacker-controlled inputs

| Boundary | Untrusted or sensitive input | Package control |
| --- | --- | --- |
| Root API | Plaintext, key references, contexts, and encoded envelopes | Fixed AES-256-GCM profile; canonical context; explicit field, count, and total-size limits; versioned parser; redacted values and failures. |
| Keyring adapter | Key references, wrapped keys, and secret-manager-delivered wrapping keys | Immutable copied keyring; fixed key count and sizes; authenticated reference and context; fresh standard-library entropy. |
| AWS KMS adapter | Key references, wrapped-key blobs, messages, signatures, client responses, and client errors | Bounds before copies or I/O; fixed algorithms and request modes; exact response key and algorithm matching; provider-cause redaction. |
| Injected collaborators | `KeyProvider`, nonce reader, and AWS SDK client implementations | Explicit construction only; no ambient discovery. Callers own collaborator correctness, concurrency, cancellation, transport, and lifecycle. |
| Persistence and observability | Persisted envelope bytes, formatted values, JSON, `slog`, errors, traces, and CloudTrail | Canonical bounded binary parsing; secret values redact text, debug, JSON, and `slog`; context is documented non-secret. |

Construction performs no network, filesystem, process, or environment access.
AWS KMS traffic occurs only after an explicit provider method call through the
injected client. The package creates no goroutines, timers, connections, global
registries, retries, or hidden caches.

## Threats and controls

| Threat | Control and evidence |
| --- | --- |
| Ciphertext or context substitution | GCM authenticates the canonical context; bundled keyring wrapping also authenticates the exact key reference and context. Context-swap and provider-authentication tests exercise rejection. |
| Key confusion or alias retargeting | AWS generation persists the resolved key ARN; decrypt and verify require exact returned key and algorithm matches. |
| Algorithm downgrade or signing abuse | The root and keyring use Go `crypto/aes`, `crypto/cipher`, and `crypto/rand`; AWS requests fix `AES_256`, `SYMMETRIC_DEFAULT`, raw-message mode, and a reviewed verify-only algorithm allowlist. No signing operation is exposed. |
| Malformed input or allocation abuse | Plaintext, envelope fields, parser totals, contexts, keyrings, KMS key references, wrapped blobs, raw messages, and signatures have explicit pre-allocation limits and exact-limit tests. The envelope parser has seeded fuzz coverage. |
| Secret disclosure through diagnostics | Payload-bearing values redact text, Go-syntax, JSON, and `slog` forms. Root and AWS provider failures discard underlying causes except canonical cancellation and deadline categories. |
| Authorization confusion | This module performs cryptographic authentication only. Applications must authorize the selected KMS key, keyring reference, signer, record owner, and operation before calling it; IAM must be scoped to exact keys and operations. |
| Retry, replay, rollback, and duplicate use | The library performs no retry and persists no replay state. Applications must authenticate stable record identity in context and own version, expiry, replay, and transactional-write policy. |
| Blocking or concurrent collaborator failure | Context reaches every provider and AWS SDK call. Local cryptographic work is size-bounded. Collaborator concurrency, prompt entropy reads, context deadlines, client timeouts, and shutdown remain explicit caller contracts. |

The module protects database payload confidentiality and integrity when the
database is exposed without simultaneous access to the authorized wrapping
key. It authenticates application-supplied context to prevent moving an
envelope between owners, records, or fields.

The module does not protect plaintext inside a compromised process, wrapping
key misuse by an authorized principal, weak application authorization, caller
logging, memory dumps, or deletion and rollback of complete valid rows.

## Requirements

- Context values must be non-secret, stable, and derived from trusted identity.
- Keyring values must be generated with cryptographic entropy, stored only in
  the approved secret manager, scoped to the application, and retained until
  every referencing envelope expires or is rewrapped.
- IAM must allow only `kms:GenerateDataKey` and `kms:Decrypt` on exact key ARNs.
- Signature-verification workloads must allow only `kms:Verify` on exact
  asymmetric signing-key ARNs and must not receive `kms:Sign`.
- Applications must use the AWS SDK default credential chain and workload
  identity rather than static credentials.
- Plaintext and decrypted values must never enter logs, traces, metrics, panic
  messages, fixtures, or error strings.
- Provider error causes must not cross the package boundary. Errors retain only
  stable package categories and safe context cancellation/deadline identity.
- Envelope fingerprints require a separate reviewed leakage analysis; a raw
  digest of a low-entropy secret can enable offline guessing.

Data-key zeroization is best effort. Go can retain compiler, stack, runtime, or
garbage-collector copies that the module cannot erase.

Keyring wrapping keys remain in process memory for the provider lifetime. This
mode trades an external KMS operation for secret-delivery portability and must
be paired with restricted process access, encrypted secret delivery, versioned
rotation, and a database threat model that excludes simultaneous application
memory compromise.

Signature verification proves only that KMS accepted the exact message,
signature, key, and algorithm. Applications must separately authorize each key
for its role, enforce replay and time policy, and canonicalize the complete
statement before verification.

Direct AWS KMS provider calls accept key references up to 2048 bytes and
decrypt ciphertext blobs up to 6144 bytes. Larger values fail before copies or
provider I/O. Calls through `Service` also inherit its stricter envelope bounds.

## Accepted risks

| ID | Severity | Owner | Rationale | Mitigation and evidence | Review condition |
| --- | --- | --- | --- | --- | --- |
| `SE-RISK-001` | Medium | Application integrator | Custom providers and the deterministic nonce-reader seam are necessary extension and test boundaries, but can violate fresh-key or nonce-uniqueness contracts. | Production uses `crypto/rand` by default; bundled providers generate fresh data keys; documentation restricts `WithNonceReader` to tests; construction and entropy-failure tests cover the seam. | Revisit for a v2 API, evidence of production misuse, or a practical test-only seam that cannot enter production builds. |
| `SE-RISK-002` | Medium | Application integrator | A universal KMS deadline would override application latency and retry budgets. A context without a deadline can therefore wait as long as the injected client permits. | Supply a bounded caller context and configure AWS SDK HTTP and retry limits; the exact context reaches each KMS call and the package adds no hidden retry. | Revisit after a stalled-call incident or when the ecosystem adopts a common provider timeout policy. |
| `SE-RISK-003` | Medium | Application operator | Go does not guarantee complete erasure of compiler, stack, runtime, or garbage-collector copies of secret bytes. | Service best-effort zeroizes transferred plaintext data keys; callers minimize plaintext lifetime, restrict process access, and disable unsafe dumps. | Revisit when Go provides enforceable secret-memory primitives or memory exposure is observed. |
| `SE-RISK-004` | Medium | Application integrator | A valid old envelope or signed statement is indistinguishable from an authorized replay without application state and time policy. | Bind stable owner, record, and field identity in context; persist versions or replay keys transactionally; include and validate statement purpose and expiry before accepting a signature. | Revisit if the module adds durable state, timestamp policy, or any replay-prevention claim. |
| `SE-RISK-005` | Medium | Direct provider caller | `DataKey` intentionally hides plaintext and exposes no destruction method, so direct provider use cannot request early clearing. | Use `Service` for managed encryption; direct callers keep the value short-lived and rely on process controls. The API and KMS guide document ownership. | Revisit for a v2 ownership redesign or evidence that direct provider use is common. |
