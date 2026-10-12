package secretenvelope

import (
	"bytes"
	"context"
	"testing"
)

// BenchmarkServiceRoundTrip measures one 1 KiB Encrypt/Decrypt pair, including
// Service construction, copied key material and best-effort key clearing.
// Context/payload setup is excluded; the recording provider and fixed nonce
// omit keyring/KMS, entropy, transport, retries and persistence workloads.
func BenchmarkServiceRoundTrip(b *testing.B) {
	provider := &recordingProvider{
		plaintextKey: bytes.Repeat([]byte{0x42}, DataKeySize),
		encryptedKey: []byte("wrapped-data-key"),
		resolvedKey:  "alias/location-contracts",
	}
	encryptionContext, _ := NewContext(map[string]string{
		"service":   "location",
		"source_id": "source-a",
	})
	plaintext := bytes.Repeat([]byte{0x42}, 1024)

	b.ReportAllocs()
	for b.Loop() {
		service, err := NewService(
			provider,
			WithNonceReader(bytes.NewReader(bytes.Repeat(
				[]byte{0x24},
				NonceSize,
			))),
		)
		if err != nil {
			b.Fatalf("NewService() error = %v", err)
		}
		envelope, err := service.Encrypt(
			context.Background(),
			EncryptRequest{
				Plaintext:    plaintext,
				KeyReference: "alias/location-contracts",
				Context:      encryptionContext,
			},
		)
		if err != nil {
			b.Fatalf("Encrypt() error = %v", err)
		}
		if _, err := service.Decrypt(
			context.Background(),
			DecryptRequest{
				Envelope: envelope,
				Context:  encryptionContext,
			},
		); err != nil {
			b.Fatalf("Decrypt() error = %v", err)
		}
	}
}
