package gocrypt

//criado em 24/10/2021 com base em https://stackoverflow.com/questions/56714284/golang-encrypting-data-using-aes
//https://play.golang.org/p/U_0pk7on1FV

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"encoding/hex"
	"fmt"
)

var (
	//key       = randBytes(256 / 8)
	gcm       cipher.AEAD
	nonceSize int
)

// Initilze GCM for both encrypting and decrypting on program start.
func Begin(hexaKey string) error {
	var key []byte
	var err error

	key, err = hex.DecodeString(hexaKey)
	if err != nil {
		return err
	}

	block, err := aes.NewCipher(key)
	if err != nil {
		return err
	}

	gcm, err = cipher.NewGCM(block)
	if err != nil {
		return err
	}

	nonceSize = gcm.NonceSize()

	return nil
}

func randBytes(length int) []byte {
	b := make([]byte, length)
	rand.Read(b)
	return b
}

func Encrypt(plainText string) string {

	var (
		byteText []byte = []byte(plainText)
	)

	nonce := randBytes(nonceSize)
	c := gcm.Seal(nil, nonce, byteText, nil)
	nonce = append(nonce, c...)

	cipherHexaText := hex.EncodeToString(nonce)

	return cipherHexaText
}

func Decrypt(hexaText string) (plaintext string, erro error) {

	byteText, err := hex.DecodeString(hexaText)
	if err != nil {
		return "", err
	}

	if len(byteText) < nonceSize {
		return "", fmt.Errorf("ciphertext too short")
	}
	nonce := byteText[0:nonceSize]
	msg := byteText[nonceSize:]

	byteText, err = gcm.Open(nil, nonce, msg, nil)
	if err != nil {
		return "", err
	}

	return string(byteText), nil
}
