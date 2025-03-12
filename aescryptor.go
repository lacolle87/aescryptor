package aescryptor

import (
	"bytes"
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"encoding/hex"
	"errors"
)

func generateAESKey(key string) ([]byte, error) {
	keyBytes := []byte(key)
	if len(keyBytes) != 32 {
		return nil, errors.New("key must be 32 bytes long for AES-256")
	}
	return keyBytes, nil
}

func generateIV() ([]byte, error) {
	iv := make([]byte, aes.BlockSize)
	if _, err := rand.Read(iv); err != nil {
		return nil, err
	}
	return iv, nil
}

func pad(plaintext []byte) []byte {
	padding := aes.BlockSize - len(plaintext)%aes.BlockSize
	return append(plaintext, bytes.Repeat([]byte{byte(padding)}, padding)...)
}

func unPad(plaintext []byte) ([]byte, error) {
	padding := plaintext[len(plaintext)-1]
	if padding > byte(len(plaintext)) {
		return nil, errors.New("invalid padding")
	}
	return plaintext[:len(plaintext)-int(padding)], nil
}

func encryptData(plaintext string, key []byte, iv []byte) ([]byte, error) {
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}

	paddedText := pad([]byte(plaintext))
	encrypter := cipher.NewCBCEncrypter(block, iv)
	ciphertext := make([]byte, len(paddedText))
	encrypter.CryptBlocks(ciphertext, paddedText)
	return ciphertext, nil
}

func decryptData(ciphertext []byte, key []byte, iv []byte) (string, error) {
	block, err := aes.NewCipher(key)
	if err != nil {
		return "", err
	}

	decrypter := cipher.NewCBCDecrypter(block, iv)
	plaintext := make([]byte, len(ciphertext))
	decrypter.CryptBlocks(plaintext, ciphertext)

	unPaddedText, err := unPad(plaintext)
	if err != nil {
		return "", err
	}
	return string(unPaddedText), nil
}

func EncryptAES(plaintext, key string) (string, error) {
	keyBytes, err := generateAESKey(key)
	if err != nil {
		return "", err
	}

	iv, err := generateIV()
	if err != nil {
		return "", err
	}

	ciphertext, err := encryptData(plaintext, keyBytes, iv)
	if err != nil {
		return "", err
	}

	combined := append(iv, ciphertext...)
	return hex.EncodeToString(combined), nil
}

func DecryptAES(ciphertextHex, key string) (string, error) {
	keyBytes, err := generateAESKey(key)
	if err != nil {
		return "", err
	}

	combined, err := hex.DecodeString(ciphertextHex)
	if err != nil {
		return "", err
	}

	if len(combined) < aes.BlockSize {
		return "", errors.New("ciphertext too short")
	}
	iv := combined[:aes.BlockSize]
	ciphertext := combined[aes.BlockSize:]

	plaintext, err := decryptData(ciphertext, keyBytes, iv)
	if err != nil {
		return "", err
	}
	return plaintext, nil
}
