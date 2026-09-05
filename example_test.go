package secretenvelope_test

import (
	"context"
	"crypto/rand"
	"fmt"

	secretenvelope "github.com/faustbrian/go-secret-envelope"
	"github.com/faustbrian/go-secret-envelope/adapters/keyring"
)

func Example() {
	wrappingKey := make([]byte, secretenvelope.DataKeySize)
	if _, err := rand.Read(wrappingKey); err != nil {
		panic(err)
	}
	provider, err := keyring.New(map[string][]byte{"customer-v1": wrappingKey})
	clear(wrappingKey)
	if err != nil {
		panic(err)
	}

	service, err := secretenvelope.NewService(provider)
	if err != nil {
		panic(err)
	}
	binding, err := secretenvelope.NewContext(map[string]string{
		"service": "example",
		"record":  "customer-42",
		"field":   "api-token",
	})
	if err != nil {
		panic(err)
	}

	envelope, err := service.Encrypt(context.Background(), secretenvelope.EncryptRequest{
		Plaintext:    []byte("secret"),
		KeyReference: "customer-v1",
		Context:      binding,
	})
	if err != nil {
		panic(err)
	}
	encoded, err := envelope.MarshalBinary()
	if err != nil {
		panic(err)
	}
	parsed, err := secretenvelope.ParseEnvelope(encoded)
	if err != nil {
		panic(err)
	}
	plaintext, err := service.Decrypt(context.Background(), secretenvelope.DecryptRequest{
		Envelope: parsed,
		Context:  binding,
	})
	if err != nil {
		panic(err)
	}

	fmt.Println(string(plaintext))
	// Output: secret
}
