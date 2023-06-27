package webhook

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"net/http"
	"time"

	"google.golang.org/protobuf/encoding/protojson"
	"google.golang.org/protobuf/proto"

	"github.com/livekit/protocol/auth"
)

const defaultWebhookTimeout = 10 * time.Second

type Notifier interface {
	Notify(ctx context.Context, payload interface{}, url string) error
}

type notifier struct {
	apiKey    string
	apiSecret string
	client    *http.Client
}

func NewNotifier(apiKey, apiSecret string) Notifier {
	return &notifier{
		apiKey:    apiKey,
		apiSecret: apiSecret,
		client: &http.Client{
			Timeout: defaultWebhookTimeout,
		},
	}
}

func (n *notifier) Notify(_ context.Context, payload interface{}, url string) error {
	var encoded []byte
	var err error
	if message, ok := payload.(proto.Message); ok {
		// use proto marshaler to ensure lowerCaseCamel
		encoded, err = protojson.Marshal(message)
	} else {
		// encode as JSON
		encoded, err = json.Marshal(payload)
	}
	if err != nil {
		return err
	}

	// sign payload
	sum := sha256.Sum256(encoded)
	b64 := base64.StdEncoding.EncodeToString(sum[:])

	at := auth.NewAccessToken(n.apiKey, n.apiSecret).
		SetValidFor(5 * time.Minute).
		SetSha256(b64)
	token, err := at.ToJWT()
	if err != nil {
		return err
	}

	r, err := http.NewRequest("POST", url, bytes.NewReader(encoded))
	if err != nil {
		return err
	}
	r.Header.Set(authHeader, token)
	// use a custom mime type to ensure signature is checked prior to parsing
	r.Header.Set("content-type", "application/webhook+json")
	_, err = n.client.Do(r)
	if err != nil {
		return err
	}

	return nil
}
