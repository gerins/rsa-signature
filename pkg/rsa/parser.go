package rsa

import (
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"encoding/pem"
	"errors"
)

const (
	PublicKeyTypeRSA     = "RSA PUBLIC KEY"
	PublicKeyDefaultType = "PUBLIC KEY"
)

func GenerateRsaKeyPair() (*rsa.PrivateKey, *rsa.PublicKey) {
	privkey, _ := rsa.GenerateKey(rand.Reader, 4096)
	return privkey, &privkey.PublicKey
}

// ParseRsaPrivateKeyFromPemStr receive private key PKCS1 format
func ParseRsaPrivateKeyFromPemStr(privPEM []byte) (*rsa.PrivateKey, error) {
	block, _ := pem.Decode(privPEM)
	if block == nil {
		return nil, errors.New("failed to parse PEM block containing the key")
	}

	priv, err := x509.ParsePKCS1PrivateKey(block.Bytes)
	if err != nil {
		parsedKey, err := x509.ParsePKCS8PrivateKey(block.Bytes)
		if err != nil {
			return nil, err
		}

		if castKey, ok := parsedKey.(*rsa.PrivateKey); ok {
			priv = castKey
		}
	}

	return priv, nil
}

// ParseRsaPublicKeyFromPemStr receive public key PKCS1 format
func ParseRsaPublicKeyFromPemStr(pubPEM []byte) (*rsa.PublicKey, error) {
	var (
		publicKey *rsa.PublicKey
		err       error
	)

	block, _ := pem.Decode(pubPEM)
	if block == nil {
		return nil, errors.New("failed to parse PEM block containing the key")
	}

	switch block.Type {
	case PublicKeyTypeRSA:
		publicKey, err = x509.ParsePKCS1PublicKey(block.Bytes)
		if err != nil {
			return nil, err
		}

	case PublicKeyDefaultType:
		pubAny, err := x509.ParsePKIXPublicKey(block.Bytes)
		if err != nil {
			return nil, err
		}

		if pubKey, ok := pubAny.(*rsa.PublicKey); ok {
			publicKey = pubKey
		}
	}

	return publicKey, nil
}
