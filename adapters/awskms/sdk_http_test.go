package awskms

import (
	"bytes"
	"context"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"reflect"
	"strings"
	"testing"
	"time"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/kms"
	"github.com/aws/aws-sdk-go-v2/service/kms/types"
	smithyhttp "github.com/aws/smithy-go/transport/http"
	secretenvelope "github.com/faustbrian/go-secret-envelope/v2"
)

const sdkFixtureKey = "arn:aws:kms:us-east-1:123456789012:key/fixture"

func sdkFixtureClient(transport sdkHTTPClientFunc) *kms.Client {
	return kms.New(kms.Options{
		Region: "us-east-1", Credentials: aws.AnonymousCredentials{},
		BaseEndpoint: aws.String("https://kms.fixture.invalid"), RetryMaxAttempts: 1,
		HTTPClient: transport,
	})
}

func sdkFixtureResponse(request *http.Request, status int, value string) (*http.Response, *sdkTrackingBody) {
	body := &sdkTrackingBody{Reader: strings.NewReader(value)}
	return &http.Response{StatusCode: status, Body: body, Request: request,
		Header: http.Header{"Content-Type": {"application/x-amz-json-1.1"}}}, body
}

func sdkFixtureContext(t *testing.T) secretenvelope.Context {
	t.Helper()
	binding, err := secretenvelope.NewContext(map[string]string{
		"Purpose": "UPPER", "purpose": "quote\" slash\\ newline\n unicode \u2603",
	})
	if err != nil {
		t.Fatal(err)
	}
	return binding
}

func TestSDKWireRoundTripPreservesEnvelopeBindings(t *testing.T) {
	binding := sdkFixtureContext(t)
	key := []byte("0123456789abcdefghijklmnopqrstuv")
	wrapped := []byte{0, 255, 1, 128, 42}
	var bodies []*sdkTrackingBody
	var targets []string
	client := sdkFixtureClient(func(request *http.Request) (*http.Response, error) {
		target := request.Header.Get("X-Amz-Target")
		targets = append(targets, target)
		var payload struct {
			KeyID               string `json:"KeyId"`
			KeySpec             string
			EncryptionAlgorithm string
			EncryptionContext   map[string]string
			CiphertextBlob      string
		}
		if err := json.NewDecoder(request.Body).Decode(&payload); err != nil {
			t.Fatal(err)
		}
		if !reflect.DeepEqual(payload.EncryptionContext, binding.Values()) {
			t.Fatalf("wire context = %#v, want exact case-sensitive binding", payload.EncryptionContext)
		}
		var response string
		switch target {
		case "TrentService.GenerateDataKey":
			if payload.KeyID != "alias/fixture" || payload.KeySpec != "AES_256" {
				t.Fatalf("unexpected generation request: %#v", payload)
			}
			response = fmt.Sprintf(`{"Plaintext":%q,"CiphertextBlob":%q,"KeyId":%q}`,
				base64.StdEncoding.EncodeToString(key), base64.StdEncoding.EncodeToString(wrapped), sdkFixtureKey)
		case "TrentService.Decrypt":
			blob, err := base64.StdEncoding.DecodeString(payload.CiphertextBlob)
			if err != nil || !bytes.Equal(blob, wrapped) || payload.KeyID != sdkFixtureKey || payload.EncryptionAlgorithm != "SYMMETRIC_DEFAULT" {
				t.Fatalf("unexpected decryption request: %#v", payload)
			}
			response = fmt.Sprintf(`{"Plaintext":%q,"KeyId":%q,"EncryptionAlgorithm":"SYMMETRIC_DEFAULT"}`,
				base64.StdEncoding.EncodeToString(key), sdkFixtureKey)
		default:
			t.Fatalf("unexpected AWS target %q", target)
		}
		result, body := sdkFixtureResponse(request, http.StatusOK, response)
		bodies = append(bodies, body)
		return result, nil
	})
	provider, err := New(client)
	if err != nil {
		t.Fatal(err)
	}
	service, err := secretenvelope.NewService(provider)
	if err != nil {
		t.Fatal(err)
	}
	plaintext := []byte("synthetic roundtrip payload")
	envelope, err := service.Encrypt(context.Background(), secretenvelope.EncryptRequest{
		Plaintext: plaintext, KeyReference: "alias/fixture", Context: binding,
	})
	if err != nil {
		t.Fatal(err)
	}
	encoded, err := envelope.MarshalBinary()
	if err != nil {
		t.Fatal(err)
	}
	parsed, err := secretenvelope.ParseEnvelope(encoded)
	if err != nil {
		t.Fatal(err)
	}
	if parsed.KeyReference() != sdkFixtureKey || !bytes.Equal(parsed.EncryptedDataKey(), wrapped) {
		t.Fatal("persisted envelope lost resolved key reference or wrapped bytes")
	}
	decoded, err := service.Decrypt(context.Background(), secretenvelope.DecryptRequest{Envelope: parsed, Context: binding})
	if err != nil || !bytes.Equal(decoded, plaintext) {
		t.Fatalf("roundtrip failed: %v", err)
	}
	if !reflect.DeepEqual(targets, []string{"TrentService.GenerateDataKey", "TrentService.Decrypt"}) {
		t.Fatalf("transport targets = %v", targets)
	}
	for _, body := range bodies {
		if !body.closed {
			t.Error("successful response body remains open")
		}
	}
}

func TestSDKVerifyWireAndFailureCategories(t *testing.T) {
	for _, fixture := range []struct {
		name     string
		status   int
		response string
		want     error
		typed    bool
	}{
		{"valid", 200, fmt.Sprintf(`{"KeyId":%q,"SigningAlgorithm":"ECDSA_SHA_256","SignatureValid":true}`, sdkFixtureKey), nil, false},
		{"false", 200, `{"SignatureValid":false}`, ErrSignatureRejected, false},
		{"typed rejection", 400, `{"__type":"KMSInvalidSignatureException","message":"synthetic-provider-private-detail"}`, ErrSignatureRejected, true},
		{"ordinary error", 400, `{"__type":"AccessDeniedException","message":"synthetic-provider-private-detail"}`, ErrKMSSignatureVerification, false},
		{"wrong algorithm", 200, fmt.Sprintf(`{"KeyId":%q,"SigningAlgorithm":"RSASSA_PSS_SHA_256","SignatureValid":true}`, sdkFixtureKey), ErrInvalidSignatureResponse, false},
		{"bad JSON", 200, `{"SignatureValid":`, ErrKMSSignatureVerification, false},
	} {
		t.Run(fixture.name, func(t *testing.T) {
			var body *sdkTrackingBody
			calls := 0
			message, signature := []byte{0, 255, 42, 1}, []byte{128, 2, 0, 254}
			client := sdkFixtureClient(func(request *http.Request) (*http.Response, error) {
				calls++
				var payload struct {
					KeyID                                             string `json:"KeyId"`
					Message, Signature, MessageType, SigningAlgorithm string
				}
				if err := json.NewDecoder(request.Body).Decode(&payload); err != nil {
					t.Fatal(err)
				}
				if request.Header.Get("X-Amz-Target") != "TrentService.Verify" || payload.KeyID != sdkFixtureKey || payload.MessageType != "RAW" || payload.SigningAlgorithm != "ECDSA_SHA_256" || payload.Message != base64.StdEncoding.EncodeToString(message) || payload.Signature != base64.StdEncoding.EncodeToString(signature) {
					t.Fatalf("unexpected Verify wire payload: %#v", payload)
				}
				response, tracking := sdkFixtureResponse(request, fixture.status, fixture.response)
				body = tracking
				return response, nil
			})
			if fixture.typed {
				_, err := client.Verify(context.Background(), &kms.VerifyInput{KeyId: aws.String(sdkFixtureKey), Message: message, Signature: signature, MessageType: types.MessageTypeRaw, SigningAlgorithm: types.SigningAlgorithmSpecEcdsaSha256})
				var typed *types.KMSInvalidSignatureException
				if !errors.As(err, &typed) {
					t.Fatalf("SDK failed to decode typed signature error: %v", err)
				}
				if !body.closed {
					t.Fatal("direct SDK error body remains open")
				}
				calls = 0
			}
			verifier, err := NewSignatureVerifier(client, types.SigningAlgorithmSpecEcdsaSha256)
			if err != nil {
				t.Fatal(err)
			}
			err = verifier.Verify(context.Background(), sdkFixtureKey, message, signature)
			if (fixture.want == nil && err != nil) || (fixture.want != nil && !errors.Is(err, fixture.want)) {
				t.Fatalf("error = %v, want %v", err, fixture.want)
			}
			if calls != 1 || body == nil || !body.closed {
				t.Fatalf("response ownership: calls=%d, body=%#v", calls, body)
			}
			if err != nil {
				var typed *types.KMSInvalidSignatureException
				if errors.As(err, &typed) || strings.Contains(fmt.Sprintf("%v %#v", err, err), "synthetic-provider-private-detail") {
					t.Fatal("adapter retained supplier details")
				}
			}
		})
	}
}

func TestSDKDataKeyFailureCategoriesAndCleanup(t *testing.T) {
	for _, fixture := range []struct {
		name, operation, response string
		status                    int
		want                      error
	}{
		{"generate service error", "generate", `{"__type":"AccessDeniedException","message":"synthetic-provider-private-detail"}`, 400, ErrKMS},
		{"decrypt service error", "decrypt", `{"__type":"AccessDeniedException","message":"synthetic-provider-private-detail"}`, 400, ErrKMS},
		{"generate invalid material", "generate", fmt.Sprintf(`{"Plaintext":"AA==","CiphertextBlob":"AQI=","KeyId":%q}`, sdkFixtureKey), 200, ErrInvalidResponse},
		{"decrypt wrong key", "decrypt", `{"Plaintext":"MDEyMzQ1Njc4OWFiY2RlZmdoaWprbG1ub3BxcnN0dXY=","KeyId":"wrong-key","EncryptionAlgorithm":"SYMMETRIC_DEFAULT"}`, 200, ErrInvalidResponse},
	} {
		t.Run(fixture.name, func(t *testing.T) {
			var body *sdkTrackingBody
			calls := 0
			client := sdkFixtureClient(func(request *http.Request) (*http.Response, error) {
				calls++
				response, tracking := sdkFixtureResponse(request, fixture.status, fixture.response)
				body = tracking
				return response, nil
			})
			provider, err := New(client)
			if err != nil {
				t.Fatal(err)
			}
			if fixture.operation == "generate" {
				var key secretenvelope.DataKey
				key, err = provider.GenerateDataKey(context.Background(), "alias/fixture", sdkFixtureContext(t))
				if len(key.EncryptedDataKey()) != 0 {
					t.Fatal("error returned a usable data key")
				}
			} else {
				var plaintext []byte
				plaintext, err = provider.DecryptDataKey(context.Background(), sdkFixtureKey, []byte("wrapped"), sdkFixtureContext(t))
				if len(plaintext) != 0 {
					t.Fatal("error returned plaintext")
				}
			}
			if !errors.Is(err, fixture.want) {
				t.Fatalf("error = %v, want %v", err, fixture.want)
			}
			if strings.Contains(fmt.Sprintf("%v %#v", err, err), "synthetic-provider-private-detail") {
				t.Fatal("adapter leaked supplier details")
			}
			if calls != 1 || body == nil || !body.closed {
				t.Fatalf("response ownership: calls=%d, body=%#v", calls, body)
			}
		})
	}
}

func TestSDKPreservesCallerCancellation(t *testing.T) {
	for _, operation := range []string{"generate", "decrypt", "verify"} {
		for _, state := range []string{"canceled", "expired", "inflight"} {
			t.Run(operation+"/"+state, func(t *testing.T) {
				ctx, cancel := context.WithCancel(context.Background())
				defer cancel()
				want := context.Canceled
				if state == "canceled" {
					cancel()
				}
				if state == "expired" {
					var deadlineCancel context.CancelFunc
					ctx, deadlineCancel = context.WithDeadline(context.Background(), time.Unix(1, 0))
					defer deadlineCancel()
					want = context.DeadlineExceeded
				}
				calls := 0
				client := sdkFixtureClient(func(request *http.Request) (*http.Response, error) {
					calls++
					if state == "inflight" {
						cancel()
					}
					<-request.Context().Done()
					return nil, request.Context().Err()
				})
				provider, err := New(client)
				if err != nil {
					t.Fatal(err)
				}
				switch operation {
				case "generate":
					var key secretenvelope.DataKey
					key, err = provider.GenerateDataKey(ctx, "alias/fixture", sdkFixtureContext(t))
					if len(key.EncryptedDataKey()) != 0 {
						t.Fatal("cancellation returned data key")
					}
				case "decrypt":
					var plaintext []byte
					plaintext, err = provider.DecryptDataKey(ctx, sdkFixtureKey, []byte("wrapped"), sdkFixtureContext(t))
					if len(plaintext) != 0 {
						t.Fatal("cancellation returned plaintext")
					}
				case "verify":
					verifier, setupErr := NewSignatureVerifier(client, types.SigningAlgorithmSpecEcdsaSha256)
					if setupErr != nil {
						t.Fatal(setupErr)
					}
					err = verifier.Verify(ctx, sdkFixtureKey, []byte("message"), []byte("signature"))
				}
				if !errors.Is(err, want) {
					t.Fatalf("cancellation = %v, want %v", err, want)
				}
				if state == "inflight" && calls != 1 {
					t.Fatalf("inflight transport calls = %d", calls)
				}
				if operation == "verify" && state != "inflight" && calls != 0 {
					t.Fatal("pre-canceled Verify performed I/O")
				}
			})
		}
	}
}

func TestSDKClosesReceivedBodiesWhenInterceptorsReject(t *testing.T) {
	for _, operation := range []string{"GenerateDataKey", "Decrypt", "Verify"} {
		for _, stage := range []string{"AfterTransmit", "BeforeDeserialization"} {
			t.Run(operation+"/"+stage, func(t *testing.T) {
				body := &sdkTrackingBody{Reader: strings.NewReader(`{"fixture":"received response"}`)}
				calls := 0
				reject := &sdkRejectResponse{stage: stage}
				client := kms.New(kms.Options{
					Region: "us-east-1", Credentials: aws.AnonymousCredentials{},
					BaseEndpoint: aws.String("https://kms.fixture.invalid"), RetryMaxAttempts: 1,
					HTTPClient: sdkHTTPClientFunc(func(request *http.Request) (*http.Response, error) {
						calls++
						return &http.Response{StatusCode: http.StatusOK, Body: body,
							Header: http.Header{"Content-Type": {"application/x-amz-json-1.1"}}, Request: request}, nil
					}),
				}, func(options *kms.Options) {
					options.Interceptors.AddAfterTransmit(reject)
					options.Interceptors.AddBeforeDeserialization(reject)
				})
				provider, err := New(client)
				if err != nil {
					t.Fatal(err)
				}
				binding, err := secretenvelope.NewContext(map[string]string{"purpose": "sdk-fixture"})
				if err != nil {
					t.Fatal(err)
				}
				switch operation {
				case "GenerateDataKey":
					var key secretenvelope.DataKey
					key, err = provider.GenerateDataKey(context.Background(), "alias/fixture", binding)
					if len(key.EncryptedDataKey()) != 0 {
						t.Error("failed generation returned usable wrapped key")
					}
				case "Decrypt":
					var plaintext []byte
					plaintext, err = provider.DecryptDataKey(context.Background(), "fixture-key", []byte("wrapped"), binding)
					if len(plaintext) != 0 {
						t.Error("failed decryption returned plaintext")
					}
				case "Verify":
					verifier, setupErr := NewSignatureVerifier(client, types.SigningAlgorithmSpecEcdsaSha256)
					if setupErr != nil {
						t.Fatal(setupErr)
					}
					err = verifier.Verify(context.Background(), "arn:aws:kms:us-east-1:123456789012:key/fixture", []byte("message"), []byte("signature"))
				}
				if err == nil {
					t.Fatal("rejected response unexpectedly succeeded")
				}
				if calls != 1 {
					t.Fatalf("transport calls = %d, want 1", calls)
				}
				if !reject.reached {
					t.Fatal("configured rejection hook was not reached")
				}
				if !body.closed {
					t.Error("received response body remains open after interceptor rejection")
				}
			})
		}
	}
}

type sdkHTTPClientFunc func(*http.Request) (*http.Response, error)

func (client sdkHTTPClientFunc) Do(request *http.Request) (*http.Response, error) {
	return client(request)
}

type sdkTrackingBody struct {
	io.Reader
	closed bool
}

func (body *sdkTrackingBody) Close() error {
	body.closed = true
	return nil
}

type sdkRejectResponse struct {
	stage   string
	reached bool
}

func (reject *sdkRejectResponse) AfterTransmit(context.Context, *smithyhttp.InterceptorContext) error {
	if reject.stage == "AfterTransmit" {
		reject.reached = true
		return errors.New("fixture response rejected")
	}
	return nil
}

func (reject *sdkRejectResponse) BeforeDeserialization(context.Context, *smithyhttp.InterceptorContext) error {
	if reject.stage == "BeforeDeserialization" {
		reject.reached = true
		return errors.New("fixture response rejected")
	}
	return nil
}
