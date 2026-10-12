// Package secretenvelope provides authenticated envelope encryption for
// application-owned secret payloads.
//
// Start with NewContext and NewService using an explicit KeyProvider. Service
// uses AES-256-GCM with a 96-bit nonce and 128-bit tag; SEV1 framing and context
// serialization are repository-owned policies, not external wire standards.
// The primitive profile is recorded against FIPS 197 (updated May 2023) and
// NIST SP 800-38D (November 2007) in docs/specification-decisions.md. This does
// not assert FIPS validation or independent cryptographic conformance.
//
// Encryption contexts are non-secret associated data. They must use stable,
// trusted identifiers and field labels, never credentials or customer payloads.
// Applications own authorization, plaintext serialization, replay/rollback
// policy, persistence and key rotation. Parsing alone does not authenticate.
//
// Values are immutable except for transferred DataKey ownership. Service starts
// no background work and borrows its provider and entropy source; concurrent use
// depends on those collaborators. Data-key clearing is best effort under Go.
// There is no cgo or root-package cloud import; the optional AWS adapter shares
// this module's dependency graph and owns its injected SDK-client boundary.
package secretenvelope
