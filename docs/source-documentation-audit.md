# Source documentation audit

[Documentation index](README.md)

## Scope and acceptance

Tier A source/API prose pass owned by the assigned documentation worker.
Base: `dfc2b3afcb7cc34b4d186d91209cee6fd89027c9` (`origin/main`).
One module: `github.com/faustbrian/go-secret-envelope/v2`; packages are the
root `secretenvelope`, `adapters/awskms`, and `adapters/keyring`.
Consumers compose Context, Service and a KeyProvider; signature consumers use
the independent KMS verify-only boundary. No executable tokens, signatures,
primitive profile, wire format, dependencies or release policy may change.
Named risks: claiming parser authentication, overstating key erasure, obscuring
transferred/borrowed bytes, nonce uniqueness, context canonicalization, provider
failure/cancellation policy, or replay/authorization ownership.
Smallest checks: Go formatting and AST documentation structure, comment-free
executable-token equality, native Go-doc generation/rendering and snapshot
stability, links/markers/generator inventory, changed-content secrets, and one
ordinary complete-final-diff review. Existing examples remain executable-unchanged;
no runtime or cryptographic qualification campaign is selected for this prose.

## Reproduce the inventory

```sh
git ls-files '*go.mod' '*.go'
cat modules.json packages.json
rg -n 'TODO|FIXME|HACK|NOTE|WARNING|Deprecated:|Code generated|go:generate|go:build' --glob '*.go'
rg '^func (Test|Example|Benchmark|Fuzz)' --glob '*_test.go'
```

One module, three packages, 19 tracked Go files. No nested module, generated
Go, vendor source, cgo, build tag, platform file, or actionable marker was
found. Canonical package comments exist but omit some entry/non-goal/lifecycle
boundaries. Missing public documentation includes error/limit declarations,
Context's error, request fields, provider/client interface methods and several
redaction methods. Existing methods need exact parser-vs-authentication,
canonical bytes, key ownership/erasure, provider-specific bounds and zero-state
contracts. These are missing/underspecified prose, not behavioral defects.

## Tracked Go files

| File | Initial investigation |
| --- | --- |
| `adapters/awskms/doc.go` | Read canonical adapter package comment; documented pinned SDK, provider trust and caller-owned resources. |
| `adapters/awskms/hardening_test.go` | Read full request/response/zeroization and hosted-error boundary assertions; no executable or comment changes needed. |
| `adapters/awskms/provider.go` | Read exact SDK requests/responses, output ownership and sanitized categories; documented exports and interface obligations. |
| `adapters/awskms/provider_test.go` | Read full recorded SDK request and resolved-identity assertions plus helpers; no prose repair needed. |
| `adapters/awskms/sdk_http_test.go` | Read full real-SDK synthetic transport, cancellation/body/interceptor cleanup fixtures; fixture scope rationale added. |
| `adapters/awskms/signature.go` | Read all bounds, ARN-shaped grammar, allowlist and response classifications; documented exports and policy rationale. |
| `adapters/awskms/signature_test.go` | Read full byte-copy, input bounds/grammar, nil/context, rejection and allowlist assertions; no prose repair needed. |
| `adapters/keyring/provider.go` | Read key copying, reference+context AAD, private wire allocation and failure cleanup; documented exports and rationale. |
| `adapters/keyring/provider_test.go` | Read full wrapping/reference/context/rotation/bound/entropy/cleanup/redaction and allocation assertions; existing names describe purpose. |
| `benchmark_test.go` | Read the 1 KiB service round-trip workload; documented included/excluded setup and synthetic-provider limits. |
| `context.go` | Read admission bounds, cloned map and length-prefixed canonical AAD; documented exports and rationale. |
| `doc.go` | Read canonical root package comment; documented primitive/non-goal/lifecycle/dependency boundaries. |
| `envelope.go` | Read every framing/parser/redaction path; documented limits, copies and structure-only admission. |
| `envelope_test.go` | Read full service/context/framing assertions and hosted diagnostic guards; recording-provider isolation rationale added. |
| `example_test.go` | Read complete keyring/Service/persistence example; executable bytes remain unchanged and no runtime rerun selected. |
| `fuzz_test.go` | Read arbitrary-byte structural round-trip invariant; documented authentication and provider non-coverage. |
| `hardening_test.go` | Read exact-limit, nil, decoder, alias/copy, invalid-key and cleanup assertions; structural-fixture rationale added. |
| `security_error_diagnostic_test.go` | Read full hosted-only provider-error identity diagnostic; preserved guard and assertions unchanged. |
| `service.go` | Read every key-transfer/clear/failure path; documented sentinels, fields, provider methods and memory/cancellation limits. |

## Rationale, markers and remaining caveats

- Every package has one canonical comment. Root/provider contexts, fields,
  interface obligations, sentinels/limits and redaction methods are repaired.
  No hand-maintained or generated module/package was skipped.
- There are no TODO/FIXME/HACK/NOTE/WARNING/deprecation/generated/build markers,
  no generators to refresh, no platform/cgo variants, and no external corpus
  rewritten. One fuzz target and one benchmark have explicit proving scope.
  Existing tests/examples retain every executable token and hosted-only guard.
- [Specification decisions](specification-decisions.md), typed records,
  [pins](../specification/manifest.tsv), conformance records and the versioned
  [threat model](security.md) support the actual primitive and policy rationale.
  External authorities were not refreshed and no standards/provider compliance
  was newly claimed.
- Key ownership is transferred, not cloned, by NewDataKey; failed construction
  leaves caller cleanup ownership. Service clears successfully transferred key
  slices on subsequent exits, not payloads, expanded AES schedules or arbitrary
  runtime copies. Keyring wrapping keys have no destruction operation.
- Custom collaborators remain trust boundaries. Fresh data keys, nonce
  uniqueness, entropy quality, prompt/noninterruptible reads, shared-use safety,
  provider wrapping authentication, application authorization and replay policy
  are explicit responsibilities, not independently proven by parser fuzzing.
- A narrow [API guide](api.md) clarification removes the implication that copied
  envelope metadata is trusted before authenticated decryption.
- Corrected current DEC-002 prose to distinguish parser admission from Service
  authentication, and current DEC-006/conformance prose to distinguish production
  defaults from caller-owned key/nonce extension points (accepted SE-RISK-001).
  Stable IDs, all old digest-list entries and every authority/source pin remain
  intact. New current canonical digests were appended to existing history;
  Unreleased records the clarification rationale and the rendered register
  mirrors the typed records. No new optional digest prose was added to the
  changelog; existing historical digest prose remains unchanged.
  No archived decision, signature or historical proof was rewritten. This is
  contract-prose reconciliation, not a runtime or cryptographic policy change.
- No unresolved source-rationale question remains; native specification
  structural validation passed after the current-record reconciliation.

## Verification and disposition

- Go 1.27.2 (the catalog producer) formatted all changed Go files;
  `git diff --check` passed.
- A task-owned standard-library AST/scanner check parsed all 19 tracked Go
  files, validated name-led documentation for 83 public declarations, fields
  and interface methods and three canonical package comments, then confirmed
  every executable token identical to the base. This includes unchanged test,
  example, fuzz, benchmark and hosted diagnostic executable contents.
- A subsequent shared strict check also covered exported methods on private
  concrete error types returned through interfaces. Seven methods now document
  their safe Error labels, category/context-only Unwrap exposure and signature
  Format redaction; exact non-comment lines and the public snapshot are unchanged.
  The subsequent native `docs check` accepted these structures but its online
  link stage failed on an unchanged README GitHub URL with HTTP 503; this is
  not a passing remote-link check. Earlier local-link validation remains
  applicable to unchanged links.
- Native `go doc -all` rendered `.`, `./adapters/awskms`, and
  `./adapters/keyring`; complete rendered contracts were inspected. Generated
  `api/baseline.txt` in that configured order using concatenated stdout trimmed
  of trailing newline bytes plus one newline. A second generation was byte-equal;
  exported type/function signature lines matched the original snapshot.
- The coordinator-supplied current-source native CLI ran
  `golib specification check`: valid one-module, ten-decision register. It also
  ran `golib docs check --local`: local documentation valid. This is local
  validation, not a claim that this CLI or package is publicly released.
- Independently checked complete inventory rows, changed JSON syntax,
  current canonical digests, preservation of all historical digest prefixes,
  equality of every current typed/rendered record, unchanged authority pins,
  local Markdown links and changed-content credential/private-key patterns.
- Ordinary complete-final-diff Tier A review found no unresolved material
  documentation, ownership, contract, scope or executable-change findings.
- Runtime, crypto, live AWS, example, race, fuzz, benchmark, consumer and release
  campaigns were not run because their executable inputs are unchanged. This
  does not reuse historical tests as fresh runtime qualification.
- Task-owned GOCACHE/GOMODCACHE/GOTMPDIR, transient checker and new native
  execution output were removed. Pre-existing tracked mutation evidence was
  preserved byte-for-byte, and the coordinator-owned CLI was retained. No
  package-specific recurring checker was added; objective shared enforcement is
  owned by the coordinated go-library-tools pass.

This audit does not claim hosted CI, remote-main delivery, public release or
live cryptographic-provider qualification. The committed source worktree stays
available for coordinator delivery.

## Objective enforcement adoption

The local `source-docs-check` target is required by ordinary/full checks and CI.
Ordinary shared CI uses `source_documentation: check` with immutable Tools
v2.4.0 and matching authenticated binary/checksum declaration. Separately
selected qualification source identities and gates remain unchanged. Structural
checks do not replace this maintained semantic audit or native docs/examples.
