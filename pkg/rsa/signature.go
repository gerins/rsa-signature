package rsa

import (
	"crypto"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"encoding/base64"
	"fmt"
	"log"
)

func GenerateSignature(payload []byte, privateKey *rsa.PrivateKey) (string, error) {
	// Before signing, we need to hash our message
	// The hash is what we actually sign
	msgHash := sha256.New()
	_, err := msgHash.Write(payload)
	if err != nil {
		return "", err
	}

	msgHashSum := msgHash.Sum(nil)

	// In order to generate the signature, we provide a random number generator,
	// our private key, the hashing algorithm that we used, and the hash sum
	// of our message
	signature, err := rsa.SignPSS(rand.Reader, privateKey, crypto.SHA256, msgHashSum, nil)
	if err != nil {
		return "", err
	}

	signatureBase64 := base64.StdEncoding.EncodeToString([]byte(signature))
	return signatureBase64, nil
}

// VerifySignature will validate payload signature
func VerifySignature(base64Signature string, payload []byte, publicKey *rsa.PublicKey) bool {
	// Before signing, we need to hash our message
	// The hash is what we actually sign
	msgHash := sha256.New()
	if _, err := msgHash.Write(payload); err != nil {
		return false
	}

	msgHashSum := msgHash.Sum(nil)

	signatureByte, err := base64.StdEncoding.DecodeString(base64Signature)
	if err != nil {
		log.Println(err)
		return false
	}

	// To verify the signature, we provide the public key, the hashing algorithm
	// the hash sum of our message and the signature we generated previously
	// there is an optional "options" parameter which can omit for now
	if err := rsa.VerifyPSS(publicKey, crypto.SHA256, msgHashSum, signatureByte, nil); err != nil {
		fmt.Println("could not verify signature: ", err)
		return false
	}

	return true
}
