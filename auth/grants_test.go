package auth

import (
	"crypto/ed25519"
	"encoding/json"
	"reflect"
	"testing"
	"time"

	"github.com/gagliardetto/solana-go"
	"github.com/go-jose/go-jose/v3"
	"github.com/go-jose/go-jose/v3/jwt"
	"github.com/stretchr/testify/require"
)

func TestGrants(t *testing.T) {
	t.Parallel()

	t.Run("clone default grant", func(t *testing.T) {
		grants := &ClaimGrants{}
		clone := grants.Clone()
		require.NotSame(t, grants, clone)
		require.Same(t, grants.Video, clone.Video)
		require.True(t, reflect.DeepEqual(grants, clone))
		require.True(t, reflect.DeepEqual(grants.Video, clone.Video))
	})

	t.Run("clone nil video", func(t *testing.T) {
		grants := &ClaimGrants{
			Identity: "identity",
			Name:     "name",
			Sha256:   "sha256",
			Metadata: "metadata",
		}
		clone := grants.Clone()
		require.NotSame(t, grants, clone)
		require.Same(t, grants.Video, clone.Video)
		require.True(t, reflect.DeepEqual(grants, clone))
		require.True(t, reflect.DeepEqual(grants.Video, clone.Video))
	})

	t.Run("clone with video", func(t *testing.T) {
		tr := true
		fa := false
		video := &VideoGrant{
			RoomCreate:     true,
			RoomList:       false,
			RoomRecord:     true,
			RoomAdmin:      false,
			RoomJoin:       true,
			Room:           "room",
			CanPublish:     &tr,
			CanSubscribe:   &fa,
			CanPublishData: nil,
			Hidden:         true,
			Recorder:       false,
		}
		grants := &ClaimGrants{
			Identity: "identity",
			Name:     "name",
			Video:    video,
			Sha256:   "sha256",
			Metadata: "metadata",
		}
		clone := grants.Clone()
		require.NotSame(t, grants, clone)
		require.NotSame(t, grants.Video, clone.Video)
		require.NotSame(t, grants.Video.CanPublish, clone.Video.CanPublish)
		require.NotSame(t, grants.Video.CanSubscribe, clone.Video.CanSubscribe)
		require.Same(t, grants.Video.CanPublishData, clone.Video.CanPublishData)
		require.True(t, reflect.DeepEqual(grants, clone))
		require.True(t, reflect.DeepEqual(grants.Video, clone.Video))
	})

	t.Run("clone copies webhook urls", func(t *testing.T) {
		grants := &ClaimGrants{WebHookURLs: []string{"https://a"}}
		clone := grants.Clone()
		require.Equal(t, grants.WebHookURLs, clone.WebHookURLs)
		clone.WebHookURLs[0] = "https://b"
		require.Equal(t, "https://a", grants.WebHookURLs[0])
	})
}

func TestAllWebHookURLs(t *testing.T) {
	t.Parallel()

	many := []string{"https://1", "https://2", "https://3", "https://4", "https://5", "https://6", "https://7"}
	tests := []struct {
		name   string
		grants *ClaimGrants
		want   []string
	}{
		{"nil grants", nil, nil},
		{"no urls", &ClaimGrants{}, nil},
		{"only empties", &ClaimGrants{WebHookURLs: []string{"", ""}}, nil},
		{"legacy only", &ClaimGrants{WebHookURL: "https://a"}, []string{"https://a"}},
		{"list only", &ClaimGrants{WebHookURLs: []string{"https://a", "https://b"}}, []string{"https://a", "https://b"}},
		{"legacy comes first", &ClaimGrants{WebHookURL: "https://z", WebHookURLs: []string{"https://a"}}, []string{"https://z", "https://a"}},
		{"backend token: ingest in both", &ClaimGrants{WebHookURL: "https://in", WebHookURLs: []string{"https://in", "https://c"}}, []string{"https://in", "https://c"}},
		{"duplicates and empties dropped", &ClaimGrants{WebHookURLs: []string{"https://a", "", "https://a", "https://b"}}, []string{"https://a", "https://b"}},
		{"capped at 6", &ClaimGrants{WebHookURLs: many}, many[:6]},
		{"cap counts legacy", &ClaimGrants{WebHookURL: "https://z", WebHookURLs: many}, append([]string{"https://z"}, many[:5]...)},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			require.Equal(t, tt.want, tt.grants.AllWebHookURLs())
		})
	}
}

// TestWebHookURLsClaims reads the claims from a token built as the backend builds it: by hand,
// without this package's AccessToken.
func TestWebHookURLsClaims(t *testing.T) {
	t.Parallel()

	key, err := solana.NewRandomPrivateKey()
	require.NoError(t, err)
	mint := func(claims map[string]interface{}) *ClaimGrants {
		signer, err := jose.NewSigner(jose.SigningKey{Algorithm: jose.EdDSA, Key: ed25519.PrivateKey(key)},
			(&jose.SignerOptions{}).WithType("JWT"))
		require.NoError(t, err)
		raw, err := jwt.Signed(signer).Claims(jwt.Claims{
			Issuer:    key.PublicKey().String(),
			Subject:   "identity",
			NotBefore: jwt.NewNumericDate(time.Now()),
			Expiry:    jwt.NewNumericDate(time.Now().Add(time.Minute)),
		}).Claims(claims).CompactSerialize()
		require.NoError(t, err)
		verifier, err := ParseAPIToken(raw)
		require.NoError(t, err)
		grants, err := verifier.Verify(key.PublicKey().String())
		require.NoError(t, err)
		return grants
	}

	t.Run("both claims", func(t *testing.T) {
		grants := mint(map[string]interface{}{
			"webHookURL":  "https://ingest",
			"webHookURLs": []string{"https://ingest", "https://customer"},
		})
		require.Equal(t, []string{"https://ingest", "https://customer"}, grants.AllWebHookURLs())
	})

	t.Run("legacy claim only", func(t *testing.T) {
		grants := mint(map[string]interface{}{"webHookURL": "https://legacy"})
		require.Empty(t, grants.WebHookURLs)
		require.Equal(t, []string{"https://legacy"}, grants.AllWebHookURLs())
	})

	t.Run("survives the node's grants json", func(t *testing.T) {
		encoded, err := json.Marshal(&ClaimGrants{WebHookURL: "https://a", WebHookURLs: []string{"https://b"}})
		require.NoError(t, err)
		require.JSONEq(t, `{"webHookURL":"https://a","webHookURLs":["https://b"]}`, string(encoded))
		decoded := &ClaimGrants{}
		require.NoError(t, json.Unmarshal(encoded, decoded))
		require.Equal(t, []string{"https://a", "https://b"}, decoded.AllWebHookURLs())
	})
}
