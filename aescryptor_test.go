package aescryptor

import (
	"crypto/aes"
	"testing"
)

const key string = "v7L0hezDBIJBc5P7YDAVJBohGTDIgYoY"

func TestGenerateIV(t *testing.T) {
	iv, err := generateIV()
	if err != nil {
		t.Fatalf("GenerateIV() error = %v", err)
	}
	if len(iv) != aes.BlockSize {
		t.Errorf("GenerateIV() = %v, want length %d", len(iv), aes.BlockSize)
	}
}

func TestEncryptDecryptAES(t *testing.T) {
	plaintext := "This is a test message"

	// Encrypt the plaintext
	ciphertextHex, err := EncryptAES(plaintext, key)
	if err != nil {
		t.Fatalf("EncryptAES() error = %v", err)
	}

	// Decrypt the ciphertext
	decryptedText, err := DecryptAES(ciphertextHex, key)
	if err != nil {
		t.Fatalf("DecryptAES() error = %v", err)
	}

	// Verify that the decrypted text matches the original plaintext
	if decryptedText != plaintext {
		t.Errorf("DecryptAES() = %v, want %v", decryptedText, plaintext)
	}
}

func TestDecryptAES_InvalidData(t *testing.T) {
	// Testing with invalid ciphertext
	invalidCiphertext := "invalidhex"
	_, err := DecryptAES(invalidCiphertext, key)
	if err == nil {
		t.Errorf("DecryptAES() expected error for invalid hex string, got nil")
	}
}

func TestDecryptAES_ShortCiphertext(t *testing.T) {
	// Testing with ciphertext that is too short to contain a valid IV and ciphertext
	shortCiphertext := "abcd" // Less than aes.BlockSize bytes for IV
	_, err := DecryptAES(shortCiphertext, key)
	if err == nil {
		t.Errorf("DecryptAES() expected error for short ciphertext, got nil")
	}
}

func TestDecryptAES_InvalidKey(t *testing.T) {
	// Encrypt with one key
	plaintext := "Another test message"
	ciphertextHex, err := EncryptAES(plaintext, key)
	if err != nil {
		t.Fatalf("EncryptAES() error = %v", err)
	}

	// Decrypt with a different key
	incorrectKey := "incorrectkey1234567890123456" // Different key
	_, err = DecryptAES(ciphertextHex, incorrectKey)
	if err == nil {
		t.Errorf("DecryptAES() expected error for incorrect key, got nil")
	}
}

func TestDecryptAES_EmptyCiphertext(t *testing.T) {
	// Test empty ciphertext string
	emptyCiphertext := ""
	_, err := DecryptAES(emptyCiphertext, key)
	if err == nil {
		t.Errorf("DecryptAES() expected error for empty ciphertext, got nil")
	}
}

func TestPadAndUnPad(t *testing.T) {
	tests := []struct {
		plaintext string
	}{
		{"short message"},                 // Standard case
		{"thismessageisblocksizealigned"}, // No padding needed
		{""},                              // Empty string
	}

	for _, tt := range tests {
		t.Run(tt.plaintext, func(t *testing.T) {
			// Test padding
			padded := pad([]byte(tt.plaintext))
			if len(padded)%aes.BlockSize != 0 {
				t.Errorf("Padding failed for %v", tt.plaintext)
			}

			// Test unpadding
			unpadded, err := unPad(padded)
			if err != nil {
				t.Errorf("Unpadding failed for %v: %v", tt.plaintext, err)
			}
			if string(unpadded) != tt.plaintext {
				t.Errorf("UnPad() = %v, want %v", string(unpadded), tt.plaintext)
			}
		})
	}
}

func TestPad_InvalidPadding(t *testing.T) {
	// Simulate invalid padding with incorrect padding byte
	incorrectPadding := []byte{1, 3, 4, 5, 6, 7, 8}
	_, err := unPad(incorrectPadding)
	if err == nil {
		t.Errorf("Expected error for invalid padding, got nil")
	}
}
