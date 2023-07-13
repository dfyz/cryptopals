package util

import (
	"crypto/aes"
	"crypto/rand"
	"encoding/base64"
	"fmt"
	"log"
	"os"
)

func PKCS7Pad(input []byte, blockSize int) []byte {
	rem := blockSize - len(input)%blockSize
	res := make([]byte, len(input)+rem)
	copy(res, input)
	for i := len(input); i < len(res); i++ {
		res[i] = byte(rem)
	}
	return res
}

const AesBlockSize = 16

func AesCbcDecrypt(ciphertext []byte, key []byte, iv []byte) (res []byte, err error) {
	if len(iv) != AesBlockSize {
		return nil, fmt.Errorf("IV had %d bytes, expected %d", len(iv), AesBlockSize)
	}

	cipher, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}

	res = make([]byte, len(ciphertext))
	prevBlock := iv
	for i := 0; i < len(ciphertext); i += AesBlockSize {
		curBlock := ciphertext[i : i+AesBlockSize]
		cipher.Decrypt(res[i:i+AesBlockSize], curBlock)
		for j := 0; j < AesBlockSize; j++ {
			res[i+j] ^= prevBlock[j]
		}
		prevBlock = curBlock
	}
	return res, nil
}

func AesCbcEncrypt(plaintext []byte, key []byte, iv []byte) (res []byte, err error) {
	if len(iv) != AesBlockSize {
		return nil, fmt.Errorf("IV had %d bytes, expected %d", len(iv), AesBlockSize)
	}

	cipher, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}

	padded := PKCS7Pad(plaintext, AesBlockSize)
	res = make([]byte, len(padded))
	prevBlock := iv
	tmpBuf := make([]byte, AesBlockSize)
	for i := 0; i < len(padded); i += AesBlockSize {
		for j := 0; j < AesBlockSize; j++ {
			tmpBuf[j] = padded[i+j] ^ prevBlock[j]
		}
		prevBlock = res[i : i+AesBlockSize]
		cipher.Encrypt(prevBlock, tmpBuf)
	}

	return res, nil
}

func AesEcbEncrypt(plaintext []byte, key []byte) (res []byte, err error) {
	cipher, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}

	padded := PKCS7Pad(plaintext, AesBlockSize)
	res = make([]byte, len(padded))
	for i := 0; i < len(res); i += AesBlockSize {
		cipher.Encrypt(res[i:i+AesBlockSize], padded[i:i+AesBlockSize])
	}
	return res, nil
}

func ReadBase64File(fileName string) (content []byte, err error) {
	b64content, err := os.ReadFile(fileName)
	if err != nil {
		return nil, err
	}

	res := make([]byte, base64.StdEncoding.DecodedLen(len(b64content)))
	bytesDecoded, err := base64.StdEncoding.Decode(res, b64content)
	if err != nil {
		return nil, err
	}

	return res[:bytesDecoded], nil
}

func RandBytes(n int) []byte {
	res := make([]byte, n)
	_, err := rand.Read(res)
	if err != nil {
		log.Fatalf("Failed to generated %d random bytes: %v", n, err)
	}
	return res
}
