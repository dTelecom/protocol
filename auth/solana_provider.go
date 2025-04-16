package auth

import (
	"github.com/gagliardetto/solana-go"
)

type SolanaKeyProvider struct {
	privateKey string
}

func NewSolanaKeyProvider(privateKey string) *SolanaKeyProvider {
	return &SolanaKeyProvider{
		privateKey: privateKey,
	}
}

func (p *SolanaKeyProvider) GetSecret(key string) string {
	return p.privateKey
}

func (p *SolanaKeyProvider) NumKeys() int {
	return 1
}

func (p *SolanaKeyProvider) GetPublicKey(address string) (string, error) {
	privateKey, err := solana.PrivateKeyFromBase58(p.privateKey)
	if err != nil {
		return "", err
	}
	return privateKey.PublicKey().String(), nil
}
