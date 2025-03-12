# aescryptor

`aescryptor` is a Go package that provides AES encryption and decryption functionality using AES-256 in CBC mode. It offers utility functions to securely encrypt and decrypt data, as well as handling padding, key management, and random or fixed IV generation.

## Features

- **AES-256 Encryption**: Supports 32-byte keys for AES-256 encryption.
- **CBC Mode**: Utilizes AES in CBC (Cipher Block Chaining) mode for encryption.
- **Padding**: Automatically adds and removes padding for data that doesn't fit the block size (16 bytes for AES).
- **Hex Encoding**: Outputs ciphertext as a hexadecimal string.
- **Secure Key and IV Generation**: Generates a 32-byte AES key and a random IV (Initialization Vector) for encryption.
- **Fixed or Random IV Option**: Allows the user to specify whether to use a fixed or random IV during encryption and decryption.

## Installation

To install the `aescryptor` package, use the following command:

```bash
go get github.com/lacolle87/aescryptor
```

## Usage

### Encrypting Data

To encrypt a plaintext message:

```go
package main

import (
	"fmt"
	"github.com/lacolle87/aescryptor"
)

func main() {
	plaintext := "This is a test message"
	key := "v7L0hezDBIJBc5P7YDAVJBohGTDIgYoY"
	useRandomIV := true // Set to false for fixed IV

	ciphertext, err := aescryptor.EncryptAES(plaintext, key, useRandomIV)
	if err != nil {
		fmt.Println("Error encrypting:", err)
		return
	}

	fmt.Println("Encrypted Ciphertext:", ciphertext)
}
```

### Decrypting Data

To decrypt a previously encrypted message:

```go
package main

import (
	"fmt"
	"github.com/lacolle87/aescryptor"
)

func main() {
	ciphertext := "yourEncryptedCiphertextHere"
	key := "v7L0hezDBIJBc5P7YDAVJBohGTDIgYoY"
	useRandomIV := true // Set to false for fixed IV

	plaintext, err := aescryptor.DecryptAES(ciphertext, key, useRandomIV)
	if err != nil {
		fmt.Println("Error decrypting:", err)
		return
	}

	fmt.Println("Decrypted Plaintext:", plaintext)
}
```

## Functions

### `EncryptAES(plaintext string, key string, useRandomIV bool) (string, error)`

Encrypts the `plaintext` using the provided `key` (32-byte string for AES-256) and returns the encrypted data as a hexadecimal string. The function can use either a fixed or random IV based on the `useRandomIV` flag.

#### Parameters
- `plaintext`: The data to encrypt.
- `key`: A 32-byte string used as the AES key.
- `useRandomIV`: A boolean flag to determine whether to use a random IV. If `false`, a fixed IV is used.

#### Returns
- The encrypted data as a hexadecimal string.
- An error if encryption fails.

### `DecryptAES(ciphertextHex string, key string, useRandomIV bool) (string, error)`

Decrypts the `ciphertextHex` (hexadecimal string) using the provided `key` and returns the decrypted plaintext. The function can handle both random and fixed IVs based on the `useRandomIV` flag.

#### Parameters
- `ciphertextHex`: The encrypted data in hexadecimal format.
- `key`: A 32-byte string used as the AES key.
- `useRandomIV`: A boolean flag to determine whether to use a random IV. If `false`, a fixed IV is used.

#### Returns
- The decrypted plaintext string.
- An error if decryption fails.

## Error Handling

The following errors may be encountered:
- **"key must be 32 bytes long for AES-256"**: The provided key must be exactly 32 bytes long.
- **"invalid padding"**: Padding error during decryption.
- **"ciphertext too short"**: Ciphertext is shorter than the block size.
- **"invalid key"**: If the key doesn't meet the required length or format.

## License

This project is licensed under the MIT License.

## Acknowledgements

- AES (Advanced Encryption Standard) is a symmetric encryption algorithm widely used in cryptographic applications.
- This package uses the Go standard library's `crypto/aes`, `crypto/cipher`, and `crypto/rand` packages.
