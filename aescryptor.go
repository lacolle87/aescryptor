package aescryptor

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"errors"
)

func generateIV() ([]byte, error) {
	iv := make([]byte, aes.BlockSize)
	_, err := rand.Read(iv)
	return iv, err
}

func generateIVFromKey(key string) ([]byte, error) {
	if len(key) != 32 {
		return nil, errors.New("key must be 32 bytes long for AES-256")
	}

	hash := sha256.New()
	hash.Write([]byte(key))
	iv := hash.Sum(nil)[:aes.BlockSize]
	return iv, nil
}

func pad(data []byte) []byte {
	padLen := aes.BlockSize - len(data)%aes.BlockSize
	padByte := byte(padLen)
	for i := 0; i < padLen; i++ {
		data = append(data, padByte)
	}
	return data
}

func unPad(data []byte) ([]byte, error) {
	if len(data) == 0 {
		return nil, errors.New("invalid padding")
	}
	padLen := int(data[len(data)-1])
	if padLen > len(data) || padLen == 0 {
		return nil, errors.New("invalid padding")
	}
	return data[:len(data)-padLen], nil
}

func encryptData(plaintext, key, iv []byte) ([]byte, error) {
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}

	plaintext = pad(plaintext)
	ciphertext := make([]byte, len(plaintext))
	cipher.NewCBCEncrypter(block, iv).CryptBlocks(ciphertext, plaintext)
	return ciphertext, nil
}

func decryptData(ciphertext, key, iv []byte) ([]byte, error) {
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}

	cipher.NewCBCDecrypter(block, iv).CryptBlocks(ciphertext, ciphertext)
	return unPad(ciphertext)
}

func EncryptAES(plaintext, key string, useRandomIV bool) (string, error) {
	var iv []byte
	var err error

	if useRandomIV {
		iv, err = generateIV()
	} else {
		iv, err = generateIVFromKey(key)
	}

	if err != nil {
		return "", err
	}

	ciphertext, err := encryptData([]byte(plaintext), []byte(key), iv)
	if err != nil {
		return "", err
	}

	return hex.EncodeToString(append(iv, ciphertext...)), nil
}

func DecryptAES(ciphertextHex, key string, useRandomIV bool) (string, error) {
	if len(key) != 32 {
		return "", errors.New("key must be 32 bytes long for AES-256")
	}

	data, err := hex.DecodeString(ciphertextHex)
	if err != nil || len(data) < aes.BlockSize {
		return "", errors.New("invalid ciphertext")
	}

	var iv []byte
	if useRandomIV {
		iv = data[:aes.BlockSize]
	} else {
		iv, err = generateIVFromKey(key)
		if err != nil {
			return "", err
		}
	}

	ciphertext := data[aes.BlockSize:]
	plaintext, err := decryptData(ciphertext, []byte(key), iv)
	if err != nil {
		return "", err
	}

	return string(plaintext), nil
}
