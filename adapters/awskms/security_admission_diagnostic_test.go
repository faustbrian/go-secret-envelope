package awskms

import (
	"bytes"
	"context"
	"errors"
	secretenvelope "github.com/faustbrian/go-secret-envelope"
	"os"
	"strings"
	"testing"
)

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
