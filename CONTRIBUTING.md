# Contributing

## Before Editing

1. Read [`AGENTS.md`](AGENTS.md) and the affected module's docs.
2. Run the standalone Go baseline below.
3. Identify owned dependencies and reverse dependants in `modules.json`.
4. Preserve unrelated work and generated/corpus provenance.

## Changes

Keep commits focused and conventional. Update every affected changelog with
the behavior and migration impact. Public API changes require compatibility
evidence and documentation. Specification behavior requires a decision record,
fixture coverage, and interoperability evidence.

New direct dependencies and dependency updates must follow the
[dependency governance policy](AGENTS.md#dependencies-and-supply-chain). Package-local
update bots are forbidden; the root policy owns every module and action update.

Specification-backed changes must follow the
[specification governance contract](AGENTS.md#design), update
the affected stable decision entries, and complete the Specification Decisions
section of the pull request template. An unresolved interpretation or stale
source pin is release-blocking; peer behavior cannot silently select policy.
The current [specification decision register](docs/specification-decisions.md)
is the change-control entry point.

Full scheduled and release mutation gates must finish with zero surviving viable
mutants. Local mutation is optional, not a universal contribution prerequisite.

Do not add package-local workflows, permanent replacements, machine-specific
paths, bypass flags, broad mutation exclusions, or aggregate quality metrics
that hide a failing package.

## Verification

Use the declared Go 1.27.2 producer; the module minimum remains Go 1.27.0.
Test independently of sibling checkouts:

```bash
GOWORK=off go test ./...
```

The module declares no services or test/build tags. Ordinary tests execute
deterministic fuzz seeds and saved corpus regressions, not active exploration.
Controlled real-SDK HTTP tests use synthetic responses and assert cancellation
and response-body ownership; they do not contact AWS or prove live credentials,
permissions or provider retries.

With the checksum-pinned public verifier selected by `.golib.yaml`, use:

```bash
make inventory
make check
make ci
```

Both Make routes run bounded local checks; `make ci` checks specification
authority offline rather than requiring an upstream network check each time.
Base-free checks run seeds/corpora; changed-source CI selects bounded active
smoke for causally affected targets. Ordinary CI consumes the public verifier
without building it from source. The separate development-only security
diagnostic retains its reviewed source runner and is not release CI.

Short active exploration selects one target; optional local mutation selects
one package:

```bash
GOMAXPROCS=2 GOWORK=off go test -run '^$' -fuzz '^FuzzParseEnvelope$' -fuzztime=2s -parallel=1 -timeout=2m .
golib mutation --module . --package ./adapters/keyring
```

`make specification-check-online` retains the explicit upstream authority route.
`make check-full` includes that route and preserves the original named
conformance selection, two-second native envelope fuzz campaign, benchmark,
full coverage, race, mutation, API, security and documentation qualification.
Crypto, envelope, provider and SDK changes need their affected hostile-input,
authentication, secret-safe error, cancellation and cleanup assertions. API
changes require compatibility and directly affected public consumers. Release
rehearsal remains `golib release dry-run --module .`. Report skipped, unavailable
and failed boundaries; local checks are not hosted-CI or public-release proof.

## Selected Weekly Assurance

The owner-level [selected-assurance caller](.github/workflows/assurance.yml) is
configured for main only, on Tuesdays at 04:07 UTC. Its single declared
root-module fuzz target receives 30 seconds of active exploration per run.
The selected target checks that successfully parsed binary envelopes re-encode
byte-for-byte. It does not certify AES-GCM authentication, entropy, provider
key handling, key zeroization, cloud KMS behavior or public-consumer compatibility;
keep the affected crypto, provider, cancellation and secret-cleanup checks.

Base-free ordinary checks execute deterministic seeds, not active exploration;
committed-range CI selects affected active smoke. Manual assurance requires an
exact anchored selector from the root fuzz operation in `.golib.yaml`, for
example `^FuzzParseEnvelope$`. Empty, unknown and malformed selections refuse.
The shared job bounds setup and execution to ten minutes, its native session
to five minutes, active workers and CPU to two, owned memory to 2 GiB, native
output to 1 MiB and private-cache lifetime. Failure, cancellation, exhausted
budgets and cleanup refusal remain attributable failures. This lane does not
run mutation or replace Required, original full fuzz budgets, explicit
`make check-full`, nested/service contracts or relevant release qualification.

## Adding A Module

Follow [repository structure policy](AGENTS.md#repository-structure). New modules
require an explicit purpose, ownership boundary, dependency review, package
catalog entry, full quality gates, documentation, changelog, license, security
policy, compatibility plan, and release dry-run.

## Source documentation

Use the authenticated Tools v2.4.0 release declared in `.golib.yaml`.
`make source-docs-check` checks all tracked Go documentation without compilation.
It is required by `make check`, `make check-full` and `make ci`; ordinary shared
CI selects the same strict check and cannot pass its required result if it fails.
Separately selected diagnostic and release qualifications keep their reviewed
source identities and scope. Semantic review and native docs remain necessary.
