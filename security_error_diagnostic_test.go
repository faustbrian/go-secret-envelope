package secretenvelope

import (
	"context"
	"errors"
	"fmt"
	"os"
	"testing"
	"time"
)

func TestServiceContainsProviderErrorIdentityHosted(t *testing.T) {
	if os.Getenv("GITHUB_ACTIONS") != "true" {
		t.Skip("provider error contract runs in hosted CI")
	}
	t.Parallel()

	canceled, cancel := context.WithCancel(context.Background())
	cancel()
	expired, release := context.WithDeadline(context.Background(), time.Unix(1, 0))
	defer release()
	configuration, err := NewContext(map[string]string{"purpose": "test"})
	if err != nil {
		t.Fatal("NewContext refused ordinary configuration")
	}
	for _, test := range []struct {
		name string
		ctx  context.Context
		want error
	}{
		{name: "ordinary", ctx: context.Background()},
		{name: "cancellation", ctx: canceled, want: context.Canceled},
		{name: "deadline", ctx: expired, want: context.DeadlineExceeded},
	} {
		t.Run(test.name, func(t *testing.T) {
			cause := errors.New("backend failure")
			if test.want != nil {
				if !errors.Is(test.ctx.Err(), test.want) {
					t.Fatal("genuine context did not reach its terminal state")
				}
				cause = fmt.Errorf("backend operation: %w", test.ctx.Err())
			}
			service, err := NewService(failingProvider{err: cause})
			if err != nil {
				t.Fatal("NewService refused explicit provider")
			}
			envelope, err := service.Encrypt(test.ctx, EncryptRequest{
				Plaintext: []byte("value"), KeyReference: "alias/example", Context: configuration,
			})
			if !errors.Is(err, ErrKeyProvider) {
				t.Fatal("Encrypt lost the stable provider category")
			}
			if test.want != nil && !errors.Is(err, test.want) {
				t.Fatal("Encrypt lost genuine context classification")
			}
			if envelope.KeyReference() != "" {
				t.Fatal("failed Encrypt returned a partial envelope")
			}
			if errors.Is(err, cause) {
				t.Fatal("Encrypt exposes arbitrary provider error identity")
			}
		})
	}
}
