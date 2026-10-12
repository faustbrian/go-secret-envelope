package awskms

import (
	"context"
	"errors"
	"reflect"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/kms"
	"github.com/aws/aws-sdk-go-v2/service/kms/types"
	secretenvelope "github.com/faustbrian/go-secret-envelope/v2"
)

const (
	maximumKeyReferenceBytes   = 2_048
	maximumCiphertextBlobBytes = 6_144
)

var (
	// ErrClientRequired reports a nil/typed-nil client or an unusable Provider.
	ErrClientRequired = errors.New("AWS KMS client is required")
	// ErrInvalidRequest reports invalid data-key inputs before client invocation.
	ErrInvalidRequest = errors.New("AWS KMS data-key request is invalid")
	// ErrKMS classifies an operational data-key client failure, retaining only
	// safe context cancellation/deadline identity instead of the client cause.
	ErrKMS = errors.New("AWS KMS data-key operation failed")
	// ErrInvalidResponse reports absent or invalid successful data-key response material.
	ErrInvalidResponse = errors.New("AWS KMS data-key response is invalid")
)

// Client is the least-privilege AWS KMS surface used by Provider. A Provider
// borrows its client and inherits the client's concurrency guarantees. When a
// client method returns an error, the client retains responsibility for any
// response and secret bytes; Provider does not inspect error responses.
type Client interface {
	// GenerateDataKey honors ctx and transfers successful output byte ownership
	// to the adapter; it must not retain mutable aliases to returned key bytes.
	GenerateDataKey(
		context.Context,
		*kms.GenerateDataKeyInput,
		...func(*kms.Options),
	) (*kms.GenerateDataKeyOutput, error)
	// Decrypt honors ctx and transfers successful plaintext ownership. If an
	// error accompanies a response, the client owns cleanup of that response.
	Decrypt(
		context.Context,
		*kms.DecryptInput,
		...func(*kms.Options),
	) (*kms.DecryptOutput, error)
}

// Provider wraps one-use AES-256 data keys with a symmetric KMS key. It owns no
// client resources or background work. Concurrent calls require a concurrent-safe
// client. Nil/zero Providers return ErrClientRequired; no Close method is provided.
type Provider struct {
	client Client
}

// New borrows a non-nil KMS client, rejecting nil/typed-nil with nil and
// ErrClientRequired. It performs no network or credential discovery.
func New(client Client) (*Provider, error) {
	if nilLike(client) {
		return nil, ErrClientRequired
	}

	return &Provider{client: client}, nil
}

// GenerateDataKey asks KMS for a fresh AES-256 key and its wrapped copy. It
// requires a non-nil ctx, nonempty reference of at most 2048 bytes, and a valid
// Context before client I/O. It fixes KeySpec to AES_256 and passes exact context
// values. On success it transfers validated output bytes without copying and
// retains the resolved response KeyId, which may differ from an input alias.
// Invalid successful responses have plaintext cleared and return a zero DataKey
// with ErrInvalidResponse; client errors wrap ErrKMS and only safe context causes.
// Direct generated keys have no destruction method; prefer managed Service use.
// Deadlines, cancellation and retries depend on ctx/the injected client.
func (provider *Provider) GenerateDataKey(
	ctx context.Context,
	keyReference string,
	encryptionContext secretenvelope.Context,
) (secretenvelope.DataKey, error) {
	if provider == nil || nilLike(provider.client) {
		return secretenvelope.DataKey{}, ErrClientRequired
	}
	contextValues := encryptionContext.Values()
	if ctx == nil || !validDataKeyReference(keyReference) || len(contextValues) == 0 {
		return secretenvelope.DataKey{}, ErrInvalidRequest
	}

	output, err := provider.client.GenerateDataKey(
		ctx,
		&kms.GenerateDataKeyInput{
			KeyId:             aws.String(keyReference),
			KeySpec:           types.DataKeySpecAes256,
			EncryptionContext: contextValues,
		},
	)
	if err != nil {
		return secretenvelope.DataKey{}, operationError{
			operation: "generate",
			kind:      ErrKMS,
			cause:     safeProviderCause(err),
		}
	}
	if output == nil {
		return secretenvelope.DataKey{}, ErrInvalidResponse
	}

	// Persist the resolved key, not a mutable alias (SECRETENVELOPE-DEC-008;
	// TestProviderGeneratesAnAES256DataKey). Successful output slices transfer
	// to DataKey; error responses retain client cleanup ownership.
	dataKey, err := secretenvelope.NewDataKey(
		output.Plaintext,
		output.CiphertextBlob,
		aws.ToString(output.KeyId),
	)
	if err != nil {
		zero(output.Plaintext)
		return secretenvelope.DataKey{}, ErrInvalidResponse
	}

	return dataKey, nil
}

// DecryptDataKey unwraps one data key with its exact key and context. It rejects
// key references and ciphertext blobs larger than AWS KMS request limits before
// copying or I/O. Requires non-nil ctx, a nonempty reference of at most 2048
// bytes, 1 through 6144 wrapped bytes and a valid Context. It copies ciphertext
// before the client call and fixes SYMMETRIC_DEFAULT. Success transfers exactly
// 32 plaintext bytes only when output KeyId matches the requested reference and
// output algorithm matches. Invalid successful output is cleared and rejected;
// errors return nil with ErrClientRequired, ErrInvalidRequest, ErrInvalidResponse,
// or an error wrapping ErrKMS and only safe context causes. Clear returned key
// bytes after use. No deadline or retry is added by the adapter.
func (provider *Provider) DecryptDataKey(
	ctx context.Context,
	keyReference string,
	ciphertext []byte,
	encryptionContext secretenvelope.Context,
) ([]byte, error) {
	if provider == nil || nilLike(provider.client) {
		return nil, ErrClientRequired
	}
	contextValues := encryptionContext.Values()
	if ctx == nil ||
		!validDataKeyReference(keyReference) ||
		len(ciphertext) == 0 ||
		len(ciphertext) > maximumCiphertextBlobBytes ||
		len(contextValues) == 0 {
		return nil, ErrInvalidRequest
	}

	output, err := provider.client.Decrypt(
		ctx,
		&kms.DecryptInput{
			KeyId:          aws.String(keyReference),
			CiphertextBlob: append([]byte(nil), ciphertext...),
			EncryptionAlgorithm: types.
				EncryptionAlgorithmSpecSymmetricDefault,
			EncryptionContext: contextValues,
		},
	)
	if err != nil {
		return nil, operationError{
			operation: "decrypt",
			kind:      ErrKMS,
			cause:     safeProviderCause(err),
		}
	}
	if output == nil ||
		len(output.Plaintext) != secretenvelope.DataKeySize ||
		aws.ToString(output.KeyId) != keyReference ||
		output.EncryptionAlgorithm !=
			types.EncryptionAlgorithmSpecSymmetricDefault {
		if output != nil {
			zero(output.Plaintext)
		}
		return nil, ErrInvalidResponse
	}

	return output.Plaintext, nil
}

type operationError struct {
	operation string
	kind      error
	cause     error
}

// Error returns an operation label without the key reference or provider error text.
func (err operationError) Error() string {
	return "AWS KMS " + err.operation + " data key failed"
}

// Unwrap exposes the failure category and, when retained, a standard context
// cancellation or deadline sentinel; it never exposes the original provider error.
func (err operationError) Unwrap() []error {
	if err.cause == nil {
		return []error{err.kind}
	}

	return []error{err.kind, err.cause}
}

func validDataKeyReference(value string) bool {
	return value != "" && len(value) <= maximumKeyReferenceBytes
}

func safeProviderCause(err error) error {
	switch {
	case errors.Is(err, context.Canceled):
		return context.Canceled
	case errors.Is(err, context.DeadlineExceeded):
		return context.DeadlineExceeded
	default:
		return nil
	}
}

func zero(value []byte) {
	for index := range value {
		value[index] = 0
	}
}

func nilLike(value any) bool {
	if value == nil {
		return true
	}
	reflected := reflect.ValueOf(value)
	switch reflected.Kind() {
	case reflect.Chan, reflect.Func, reflect.Interface, reflect.Map,
		reflect.Pointer, reflect.Slice:
		return reflected.IsNil()
	default:
		return false
	}
}

var _ secretenvelope.KeyProvider = (*Provider)(nil)
