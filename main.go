package main

import (
	"fmt"
	"log"
	"os"
	"rsa-signature/pkg/rsa"
)

var payload = "Secret message"

func main() {
	privateKey, err := os.ReadFile("./files/id_rsa")
	if err != nil {
		log.Fatal(err)
	}

	parsedPrivateKey, err := rsa.ParseRsaPrivateKeyFromPemStr(privateKey)
	if err != nil {
		log.Fatal(err)
	}

	publicKey, err := os.ReadFile("./files/id_rsa.pub")
	if err != nil {
		log.Fatal(err)
	}

	parsedPublicKey, err := rsa.ParseRsaPublicKeyFromPemStr(publicKey)
	if err != nil {
		log.Fatal(err)
	}

	signature, err := rsa.GenerateSignature([]byte(payload), parsedPrivateKey)
	if err != nil {
		log.Fatal(err)
	}

	if rsa.VerifySignature(signature, []byte(payload), parsedPublicKey) {
		fmt.Println("signature is verified")
	}
}
