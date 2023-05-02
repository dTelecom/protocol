package auth

import (
	p2p_database "github.com/dTelecom/p2p-realtime-database"
)

type EthKeyProvider struct {
	wallet     string
	privateKey string

	contract p2p_database.EthSmartContract
}

func NewEthKeyProvider(contract p2p_database.EthSmartContract, wallet, privateKey string) *EthKeyProvider {
	return &EthKeyProvider{
		wallet:     wallet,
		privateKey: privateKey,
		contract:   contract,
	}
}

func (p *EthKeyProvider) GetSecret(key string) string {
	return p.privateKey
}

func (p *EthKeyProvider) NumKeys() int {
	return 1
}

func (p *EthKeyProvider) GetPublicKey(address string) string {
	pubKey, err := p.contract.PublicKeyByAddress(address)
	if err != nil {
		return ""
	}
	return pubKey
}
