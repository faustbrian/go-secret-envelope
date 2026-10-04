package awskms

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"os"
	"strings"
	"testing"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/kms"
	"github.com/aws/aws-sdk-go-v2/service/kms/types"
	secretenvelope "github.com/faustbrian/go-secret-envelope/v2"
)

func TestProviderRejectsNilClientsAndReceivers(t *testing.T) {
	t.Parallel()

	var typedNil *recordingClient
	for name, client := range map[string]Client{
		"nil":       nil,
		"typed-nil": typedNil,
	} {
		t.Run(name, func(t *testing.T) {
			t.Parallel()

			if _, err := New(client); !errors.Is(err, ErrClientRequired) {
				t.Fatalf("New() error = %v, want ErrClientRequired", err)
			}
		})
	}
	if !nilLike(nil) || !nilLike(typedNil) || nilLike(42) {
		t.Fatal("nilLike() classification is incorrect")
	}

	var provider *Provider
	encryptionContext, _ := secretenvelope.NewContext(
		map[string]string{"service": "location"},
	)
	if _, err := provider.GenerateDataKey(
		context.Background(),
		"alias/location",
		encryptionContext,
	); !errors.Is(err, ErrClientRequired) {
		t.Fatalf("nil GenerateDataKey() error = %v", err)
	}
	if _, err := provider.DecryptDataKey(
		context.Background(),
		"alias/location",
		[]byte("wrapped"),
		encryptionContext,
	); !errors.Is(err, ErrClientRequired) {
		t.Fatalf("nil DecryptDataKey() error = %v", err)
	}
}

func TestProviderRejectsInvalidRequests(t *testing.T) {
	t.Parallel()

	provider, _ := New(&recordingClient{})
	encryptionContext, _ := secretenvelope.NewContext(
		map[string]string{"service": "location"},
	)
	for name, test := range map[string]struct {
		ctx          context.Context
		keyReference string
		ciphertext   []byte
		context      secretenvelope.Context
		decrypt      bool
	}{
		"generate-context": {
			ctx:          context.Background(),
			keyReference: "alias/location",
		},
		"generate-key": {
			ctx:     context.Background(),
			context: encryptionContext,
		},
		"generate-go-context": {
			keyReference: "alias/location",
			context:      encryptionContext,
		},
		"decrypt-context": {
			ctx:          context.Background(),
			keyReference: "alias/location",
			ciphertext:   []byte("wrapped"),
			decrypt:      true,
		},
		"decrypt-key": {
			ctx:        context.Background(),
			ciphertext: []byte("wrapped"),
			context:    encryptionContext,
			decrypt:    true,
		},
		"decrypt-ciphertext": {
			ctx:          context.Background(),
			keyReference: "alias/location",
			context:      encryptionContext,
			decrypt:      true,
		},
		"decrypt-go-context": {
			keyReference: "alias/location",
			ciphertext:   []byte("wrapped"),
			context:      encryptionContext,
			decrypt:      true,
		},
	} {
		t.Run(name, func(t *testing.T) {
			t.Parallel()

			var err error
			if test.decrypt {
				_, err = provider.DecryptDataKey(
					test.ctx,
					test.keyReference,
					test.ciphertext,
					test.context,
				)
			} else {
				_, err = provider.GenerateDataKey(
					test.ctx,
					test.keyReference,
					test.context,
				)
			}
			if !errors.Is(err, ErrInvalidRequest) {
				t.Fatalf("operation error = %v, want ErrInvalidRequest", err)
			}
		})
	}
}

func TestProviderRejectsOversizedRequestsBeforeKMS(t *testing.T) {
	if os.Getenv("GITHUB_ACTIONS") != "true" {
		t.Skip("KMS admission regression runs in hosted CI")
	}
	t.Parallel()

	const (
		maximumKeyReferenceBytes   = 2_048
		maximumCiphertextBlobBytes = 6_144
	)
	encryptionContext, _ := secretenvelope.NewContext(
		map[string]string{"service": "location"},
	)
	for name, test := range map[string]struct {
		keyReference string
		ciphertext   []byte
		decrypt      bool
	}{
		"generate-key-reference": {
			keyReference: strings.Repeat("k", maximumKeyReferenceBytes+1),
		},
		"decrypt-key-reference": {
			keyReference: strings.Repeat("k", maximumKeyReferenceBytes+1),
			ciphertext:   []byte("wrapped"),
			decrypt:      true,
		},
		"decrypt-ciphertext": {
			keyReference: "alias/location",
			ciphertext:   bytes.Repeat([]byte{0x42}, maximumCiphertextBlobBytes+1),
			decrypt:      true,
		},
	} {
		t.Run(name, func(t *testing.T) {
			t.Parallel()

			client := &recordingClient{}
			provider, _ := New(client)
			var err error
			if test.decrypt {
				_, err = provider.DecryptDataKey(
					context.Background(),
					test.keyReference,
					test.ciphertext,
					encryptionContext,
				)
			} else {
				_, err = provider.GenerateDataKey(
					context.Background(),
					test.keyReference,
					encryptionContext,
				)
			}
			if !errors.Is(err, ErrInvalidRequest) {
				t.Fatalf("operation error = %v, want ErrInvalidRequest", err)
			}
			if client.generateInput != nil || client.decryptInput != nil {
				t.Fatal("oversized request reached KMS client")
			}
		})
	}

	generateClient := &recordingClient{}
	provider, _ := New(generateClient)
	_, generateErr := provider.GenerateDataKey(
		context.Background(),
		strings.Repeat("k", maximumKeyReferenceBytes),
		encryptionContext,
	)
	if !errors.Is(generateErr, ErrInvalidResponse) || generateClient.generateInput == nil {
		t.Fatalf("exact-limit GenerateDataKey() error = %v", generateErr)
	}

	decryptClient := &recordingClient{}
	provider, _ = New(decryptClient)
	_, decryptErr := provider.DecryptDataKey(
		context.Background(),
		strings.Repeat("k", maximumKeyReferenceBytes),
		bytes.Repeat([]byte{0x42}, maximumCiphertextBlobBytes),
		encryptionContext,
	)
	if !errors.Is(decryptErr, ErrInvalidResponse) || decryptClient.decryptInput == nil {
		t.Fatalf("exact-limit DecryptDataKey() error = %v", decryptErr)
	}
}

func TestProviderRejectsInvalidGenerateResponsesAndZeroizesKeys(t *testing.T) {
	t.Parallel()

	const resolvedKey = "arn:aws:kms:eu-north-1:123456789012:key/example"
	encryptionContext, _ := secretenvelope.NewContext(
		map[string]string{"service": "location"},
	)
	for name, output := range map[string]*kms.GenerateDataKeyOutput{
		"nil": nil,
		"key-size": {
			Plaintext:      []byte{0x42},
			CiphertextBlob: []byte("wrapped"),
			KeyId:          aws.String(resolvedKey),
		},
		"ciphertext": {
			Plaintext: bytes.Repeat(
				[]byte{0x42},
				secretenvelope.DataKeySize,
			),
			KeyId: aws.String(resolvedKey),
		},
		"key-reference": {
			Plaintext: bytes.Repeat(
				[]byte{0x42},
				secretenvelope.DataKeySize,
			),
			CiphertextBlob: []byte("wrapped"),
		},
	} {
		t.Run(name, func(t *testing.T) {
			t.Parallel()

			client := &recordingClient{generateOutput: output}
			provider, _ := New(client)
			_, err := provider.GenerateDataKey(
				context.Background(),
				"alias/location",
				encryptionContext,
			)
			if !errors.Is(err, ErrInvalidResponse) {
				t.Fatalf(
					"GenerateDataKey() error = %v, want ErrInvalidResponse",
					err,
				)
			}
			if output != nil && !allZero(output.Plaintext) {
				t.Fatal("invalid plaintext key was not zeroized")
			}
		})
	}
}

func TestProviderRejectsDecryptFailuresAndMalformedResponses(t *testing.T) {
	t.Parallel()

	const (
		resolvedKey = "arn:aws:kms:eu-north-1:123456789012:key/example"
		secret      = "kms-decrypt-secret"
	)
	encryptionContext, _ := secretenvelope.NewContext(
		map[string]string{"service": "location"},
	)
	provider, _ := New(&recordingClient{
		decryptErr: errors.New(secret),
	})
	_, err := provider.DecryptDataKey(
		context.Background(),
		resolvedKey,
		[]byte("wrapped"),
		encryptionContext,
	)
	if !errors.Is(err, ErrKMS) || strings.Contains(err.Error(), secret) {
		t.Fatalf("DecryptDataKey() error = %v", err)
	}

	for name, output := range map[string]*kms.DecryptOutput{
		"nil": nil,
		"key-size": {
			Plaintext:           []byte{0x42},
			KeyId:               aws.String(resolvedKey),
			EncryptionAlgorithm: types.EncryptionAlgorithmSpecSymmetricDefault,
		},
		"key-reference": {
			Plaintext: bytes.Repeat(
				[]byte{0x42},
				secretenvelope.DataKeySize,
			),
			KeyId:               aws.String("different-key"),
			EncryptionAlgorithm: types.EncryptionAlgorithmSpecSymmetricDefault,
		},
		"algorithm": {
			Plaintext: bytes.Repeat(
				[]byte{0x42},
				secretenvelope.DataKeySize,
			),
			KeyId: aws.String(resolvedKey),
		},
	} {
		t.Run(name, func(t *testing.T) {
			t.Parallel()

			client := &recordingClient{decryptOutput: output}
			provider, _ := New(client)
			_, err := provider.DecryptDataKey(
				context.Background(),
				resolvedKey,
				[]byte("wrapped"),
				encryptionContext,
			)
			if !errors.Is(err, ErrInvalidResponse) {
				t.Fatalf(
					"DecryptDataKey() error = %v, want ErrInvalidResponse",
					err,
				)
			}
			if output != nil && !allZero(output.Plaintext) {
				t.Fatal("invalid plaintext key was not zeroized")
			}
		})
	}
}

func TestOperationErrorDoesNotExposeCause(t *testing.T) {
	if os.Getenv("GITHUB_ACTIONS") != "true" {
		t.Skip("provider error contract runs in hosted CI")
	}
	t.Parallel()

	cause := errors.New("sensitive-cause")
	encryptionContext, _ := secretenvelope.NewContext(
		map[string]string{"service": "location"},
	)
	for name, test := range map[string]struct {
		client    *recordingClient
		operation func(*Provider) error
		wantText  string
	}{
		"generate": {
			client: &recordingClient{generateErr: cause},
			operation: func(provider *Provider) error {
				_, err := provider.GenerateDataKey(
					context.Background(), "alias/location", encryptionContext,
				)

				return err
			},
			wantText: "AWS KMS generate data key failed",
		},
		"decrypt": {
			client: &recordingClient{decryptErr: cause},
			operation: func(provider *Provider) error {
				_, err := provider.DecryptDataKey(
					context.Background(), "alias/location", []byte("wrapped"),
					encryptionContext,
				)

				return err
			},
			wantText: "AWS KMS decrypt data key failed",
		},
	} {
		t.Run(name, func(t *testing.T) {
			t.Parallel()

			provider, _ := New(test.client)
			err := test.operation(provider)
			if !errors.Is(err, ErrKMS) || errors.Is(err, cause) ||
				err.Error() != test.wantText {
				t.Fatalf("operation error = %v", err)
			}
			if rendered := fmt.Sprintf("%v %#v", err, err); strings.Contains(rendered, cause.Error()) {
				t.Fatal("formatted operation error exposed its cause")
			}
		})
	}
}

func TestOperationErrorPreservesOnlySafeCancellation(t *testing.T) {
	if os.Getenv("GITHUB_ACTIONS") != "true" {
		t.Skip("provider cancellation contract runs in hosted CI")
	}
	t.Parallel()

	encryptionContext, _ := secretenvelope.NewContext(
		map[string]string{"service": "location"},
	)
	for name, test := range map[string]struct {
		cause     error
		operation func(*Provider) error
	}{
		"generate-canceled": {
			cause: context.Canceled,
			operation: func(provider *Provider) error {
				_, err := provider.GenerateDataKey(
					context.Background(), "alias/location", encryptionContext,
				)

				return err
			},
		},
		"generate-deadline": {
			cause: context.DeadlineExceeded,
			operation: func(provider *Provider) error {
				_, err := provider.GenerateDataKey(
					context.Background(), "alias/location", encryptionContext,
				)

				return err
			},
		},
		"decrypt-canceled": {
			cause: context.Canceled,
			operation: func(provider *Provider) error {
				_, err := provider.DecryptDataKey(
					context.Background(), "alias/location", []byte("wrapped"),
					encryptionContext,
				)

				return err
			},
		},
		"decrypt-deadline": {
			cause: context.DeadlineExceeded,
			operation: func(provider *Provider) error {
				_, err := provider.DecryptDataKey(
					context.Background(), "alias/location", []byte("wrapped"),
					encryptionContext,
				)

				return err
			},
		},
	} {
		t.Run(name, func(t *testing.T) {
			t.Parallel()

			client := &recordingClient{generateErr: test.cause, decryptErr: test.cause}
			provider, _ := New(client)
			err := test.operation(provider)
			if !errors.Is(err, ErrKMS) || !errors.Is(err, test.cause) {
				t.Fatalf("operation error = %v, want KMS and cancellation categories", err)
			}
		})
	}
}

func allZero(value []byte) bool {
	for _, item := range value {
		if item != 0 {
			return false
		}
	}

	return true
}
