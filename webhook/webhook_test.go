package webhook_test

import (
	"context"
	"encoding/json"
	"net"
	"net/http"
	"net/http/httptest"
	"sync"
	"testing"
	"time"

	"github.com/gagliardetto/solana-go"
	"github.com/stretchr/testify/require"

	"github.com/livekit/protocol/auth"
	"github.com/livekit/protocol/livekit"
	"github.com/livekit/protocol/webhook"
)

const webhookURL = "http://localhost:8765"

func TestWebHook(t *testing.T) {
	s := newServer(":8765")
	require.NoError(t, s.Start())
	defer s.Stop()

	// keys are Solana keypairs: the notifier signs with the private key, the receiver verifies with the public one
	key, err := solana.NewRandomPrivateKey()
	require.NoError(t, err)
	apiKey := key.PublicKey().String()
	authProvider := auth.NewSimpleKeyProvider(apiKey, apiKey)
	notifier := webhook.NewNotifier(apiKey, key.String())

	t.Run("test json payload", func(t *testing.T) {
		payload := map[string]interface{}{
			"test": "payload",
			"nested": map[string]interface{}{
				"structure": true,
			},
		}

		wg := sync.WaitGroup{}
		wg.Add(1)
		s.handler = func(r *http.Request) {
			defer wg.Done()
			// receive logic
			data, err := webhook.Receive(r, authProvider)
			require.NoError(t, err)

			var decoded map[string]interface{}
			require.NoError(t, json.Unmarshal(data, &decoded))

			require.EqualValues(t, decoded, payload)
		}

		require.NoError(t, notifier.Notify(context.Background(), payload, webhookURL))
		wg.Wait()
	})

	t.Run("test event payload", func(t *testing.T) {
		event := &livekit.WebhookEvent{
			Event: webhook.EventTrackPublished,
			Participant: &livekit.ParticipantInfo{
				Identity: "test",
			},
			Track: &livekit.TrackInfo{
				Sid: "TR_abcde",
			},
		}

		wg := sync.WaitGroup{}
		wg.Add(1)
		s.handler = func(r *http.Request) {
			defer wg.Done()
			decodedEvent, err := webhook.ReceiveWebhookEvent(r, authProvider)
			require.NoError(t, err)

			require.EqualValues(t, event, decodedEvent)
		}
		require.NoError(t, notifier.Notify(context.Background(), event, webhookURL))
		wg.Wait()
	})

}

// TestNotifyClosesResponseBody: an unclosed body holds the connection until the client timeout.
func TestNotifyClosesResponseBody(t *testing.T) {
	closed := make(chan struct{}, 1)
	server := httptest.NewUnstartedServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		_, _ = w.Write([]byte("ok"))
	}))
	server.Config.ConnState = func(_ net.Conn, state http.ConnState) {
		if state == http.StateClosed {
			closed <- struct{}{}
		}
	}
	server.Start()
	defer server.Close()

	key, err := solana.NewRandomPrivateKey()
	require.NoError(t, err)
	notifier := webhook.NewNotifier(key.PublicKey().String(), key.String())
	require.NoError(t, notifier.Notify(context.Background(), map[string]string{"a": "b"}, server.URL))

	select {
	case <-closed:
	case <-time.After(2 * time.Second):
		t.Fatal("connection still held after Notify returned")
	}
}

type testServer struct {
	handler func(r *http.Request)
	server  *http.Server
}

func newServer(addr string) *testServer {
	s := &testServer{}
	s.server = &http.Server{
		Addr:    addr,
		Handler: s,
	}
	return s
}

func (s *testServer) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	if s.handler != nil {
		s.handler(r)
	}
}

func (s *testServer) Start() error {
	l, err := net.Listen("tcp", s.server.Addr)
	if err != nil {
		return err
	}
	go s.server.Serve(l)
	return nil
}

func (s *testServer) Stop() {
	_ = s.server.Shutdown(context.Background())
}
