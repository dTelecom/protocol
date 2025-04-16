package auth

import (
	"time"

	"crypto/ed25519"
	"github.com/gagliardetto/solana-go"

	"github.com/go-jose/go-jose/v3/jwt"
)

type APIKeyTokenVerifier struct {
	token    *jwt.JSONWebToken
	identity string
	apiKey   string
}

// ParseAPIToken parses an encoded JWT token and
func ParseAPIToken(raw string) (*APIKeyTokenVerifier, error) {
	tok, err := jwt.ParseSigned(raw)
	if err != nil {
		return nil, err
	}

	out := jwt.Claims{}
	if err := tok.UnsafeClaimsWithoutVerification(&out); err != nil {
		return nil, err
	}

	v := &APIKeyTokenVerifier{
		token:    tok,
		apiKey:   out.Issuer,
		identity: out.Subject,
	}
	if v.identity == "" {
		v.identity = out.ID
	}
	return v, nil
}

// APIKey returns the API key this token was signed with
func (v *APIKeyTokenVerifier) APIKey() string {
	return v.apiKey
}

func (v *APIKeyTokenVerifier) Identity() string {
	return v.identity
}

func (v *APIKeyTokenVerifier) Verify(key interface{}) (*ClaimGrants, error) {
	s, ok := key.(string)
	if !ok {
		return nil, ErrKeysMissing
	}

	pubKeyB, err := solana.PublicKeyFromBase58(s)
	if err != nil {
		return nil, err
	}

	pubKey := ed25519.PublicKey(pubKeyB[:])

	out := jwt.Claims{}
	claims := ClaimGrants{}
	if err := v.token.Claims(pubKey, &out, &claims); err != nil {
		return nil, err
	}
	if err := out.Validate(jwt.Expected{Issuer: v.apiKey, Time: time.Now()}); err != nil {
		return nil, err
	}

	// copy over identity
	claims.Identity = v.identity
	return &claims, nil
}
