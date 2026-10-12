package awskms

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"io"
	"strings"
	"unicode"
	"unicode/utf8"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/kms"
	"github.com/aws/aws-sdk-go-v2/service/kms/types"
)

const (
	maximumRawSignatureMessageBytes = 4096
	maximumSignatureBytes           = 1024
	maximumSignatureKeyBytes        = 2048
)

var (
	// ErrInvalidSignatureVerifier means construction or receiver state is not
	// safe for signature verification.
	ErrInvalidSignatureVerifier = errors.New(
		"AWS KMS signature verifier is invalid",
	)
	// ErrInvalidSignatureRequest means the key, message, signature, or context
	// cannot be sent to KMS safely.
	ErrInvalidSignatureRequest = errors.New(
		"AWS KMS signature verification request is invalid",
	)
	// ErrKMSSignatureVerification means KMS could not execute verification.
	ErrKMSSignatureVerification = errors.New(
		"AWS KMS signature verification failed",
	)
	// ErrSignatureRejected means KMS authenticated neither the message nor its
	// signature with the configured key and algorithm.
	ErrSignatureRejected = errors.New("AWS KMS signature was rejected")
	// ErrInvalidSignatureResponse means KMS returned an incomplete or
	// contradictory successful response.
	ErrInvalidSignatureResponse = errors.New(
		"AWS KMS signature verification response is invalid",
	)
)

// SignatureClient is the least-privilege AWS KMS surface used to authenticate
// an externally signed statement. SignatureVerifier borrows the client and
// inherits its concurrency guarantees. It must honor caller context; client
// configuration owns network deadlines, retries and response-body cleanup.
type SignatureClient interface {
	// Verify returns the verification result for the exact supplied RAW message,
	// signature, key and algorithm. Successful output must identify that key and
	// algorithm; the adapter checks both rather than trusting transport success.
	Verify(
		context.Context,
		*kms.VerifyInput,
		...func(*kms.Options),
	) (*kms.VerifyOutput, error)
}

// SignatureVerifier authenticates bounded raw messages with one explicitly
// reviewed asymmetric KMS signing algorithm. It never signs messages and owns
// no client resources or background work. Its zero value is invalid, and
// concurrent Verify calls require a concurrent-safe client. There is no Close
// or resource destruction operation.
type SignatureVerifier struct {
	client    SignatureClient
	algorithm types.SigningAlgorithmSpec
}

// NewSignatureVerifier validates the KMS client and fixes the accepted
// algorithm for the verifier's lifetime. Accepted choices are RSASSA-PSS
// SHA-256/384/512, ECDSA SHA-256/384/512, and ED25519_SHA_512 in RAW mode.
// Nil/typed-nil clients and all other algorithms return nil with
// ErrInvalidSignatureVerifier. Construction performs no I/O or key discovery.
func NewSignatureVerifier(
	client SignatureClient,
	algorithm types.SigningAlgorithmSpec,
) (*SignatureVerifier, error) {
	if nilLike(client) || !validRawSignatureAlgorithm(algorithm) {
		return nil, ErrInvalidSignatureVerifier
	}

	return &SignatureVerifier{client: client, algorithm: algorithm}, nil
}

// Verify authenticates one exact raw message. The method owns copies of caller
// bytes before invoking KMS and returns stable, secret-safe failure classes.
// KeyReference must be a nonempty KMS key-ARN-shaped UTF-8 string (no controls
// or surrounding whitespace), at most 2048 bytes; aliases are rejected. Message
// is 1 through 4096 raw bytes, signature 1 through 1024 bytes, and ctx is non-nil.
// Inputs are borrowed while copying; do not mutate them concurrently.
//
// Already-canceled ctx returns ctx.Err() without I/O. Client failures wrap
// ErrKMSSignatureVerification, except KMSInvalidSignatureException wraps
// ErrSignatureRejected; only safe context cancellation/deadline causes survive.
// A false response is ErrSignatureRejected; nil, wrong-key or wrong-algorithm
// successful responses are ErrInvalidSignatureResponse. No retry/deadline is
// added. Success means KMS confirmed these exact bytes, not signer authorization,
// statement canonicalization, freshness or replay prevention.
func (verifier *SignatureVerifier) Verify(
	ctx context.Context,
	keyReference string,
	message []byte,
	signature []byte,
) error {
	if verifier == nil || nilLike(verifier.client) ||
		!validRawSignatureAlgorithm(verifier.algorithm) {
		return ErrInvalidSignatureVerifier
	}
	if ctx == nil || !validSignatureKeyReference(keyReference) ||
		len(message) == 0 ||
		len(message) > maximumRawSignatureMessageBytes ||
		len(signature) == 0 || len(signature) > maximumSignatureBytes {
		return ErrInvalidSignatureRequest
	}
	if err := ctx.Err(); err != nil {
		return err
	}
	output, err := verifier.client.Verify(ctx, &kms.VerifyInput{
		KeyId:            aws.String(keyReference),
		Message:          bytes.Clone(message),
		MessageType:      types.MessageTypeRaw,
		Signature:        bytes.Clone(signature),
		SigningAlgorithm: verifier.algorithm,
	})
	if err != nil {
		kind := ErrKMSSignatureVerification
		var rejected *types.KMSInvalidSignatureException
		if errors.As(err, &rejected) {
			kind = ErrSignatureRejected
		}

		return signatureOperationError{
			kind:  kind,
			cause: safeProviderCause(err),
		}
	}
	// Transport success is not authentication. Require a positive result and
	// exact key/algorithm identity (SECRETENVELOPE-DEC-010;
	// TestSignatureVerifierClassifiesFailuresWithoutRenderingCauses).
	if output == nil {
		return ErrInvalidSignatureResponse
	}
	if !output.SignatureValid {
		return ErrSignatureRejected
	}
	if aws.ToString(output.KeyId) != keyReference ||
		output.SigningAlgorithm != verifier.algorithm {
		return ErrInvalidSignatureResponse
	}

	return nil
}

// This allowlist is owned policy, not every value in the pinned SDK enum.
// Extending it needs attributable scheme review (SECRETENVELOPE-DEC-009;
// TestSignatureVerifierAcceptsReviewedRawAlgorithms).
func validRawSignatureAlgorithm(
	algorithm types.SigningAlgorithmSpec,
) bool {
	switch algorithm {
	case types.SigningAlgorithmSpecRsassaPssSha256,
		types.SigningAlgorithmSpecRsassaPssSha384,
		types.SigningAlgorithmSpecRsassaPssSha512,
		types.SigningAlgorithmSpecEcdsaSha256,
		types.SigningAlgorithmSpecEcdsaSha384,
		types.SigningAlgorithmSpecEcdsaSha512,
		types.SigningAlgorithmSpecEd25519Sha512:
		return true
	default:
		return false
	}
}

func validSignatureKeyReference(value string) bool {
	if value == "" {
		return false
	}
	if len(value) > maximumSignatureKeyBytes {
		return false
	}
	if strings.TrimSpace(value) != value {
		return false
	}
	if !utf8.ValidString(value) {
		return false
	}
	for _, character := range value {
		if unicode.IsControl(character) {
			return false
		}
	}
	parts := strings.SplitN(value, ":", 6)
	if len(parts) != 6 || parts[0] != "arn" || parts[1] == "" ||
		parts[2] != "kms" || parts[3] == "" || parts[4] == "" ||
		!strings.HasPrefix(parts[5], "key/") || len(parts[5]) == len("key/") {
		return false
	}

	return true
}

type signatureOperationError struct {
	kind  error
	cause error
}

func (err signatureOperationError) Error() string {
	return "AWS KMS signature verification failed"
}

func (err signatureOperationError) Unwrap() []error {
	if err.cause == nil {
		return []error{err.kind}
	}

	return []error{err.kind, err.cause}
}

func (err signatureOperationError) Format(state fmt.State, _ rune) {
	_, _ = io.WriteString(state, err.Error())
}
