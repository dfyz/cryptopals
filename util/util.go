package util

import (
	"crypto/aes"
	"crypto/rand"
	"encoding/base64"
	"fmt"
	"log"
	"os"
	"strings"
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

func PKCS7Unpad(input []byte, blockSize int) ([]byte, error) {
	if len(input) == 0 || len(input)%blockSize != 0 {
		return nil, fmt.Errorf("invalid input length for block size %d: %d", blockSize, len(input))
	}

	nPad := int(input[len(input)-1])
	if nPad > blockSize {
		return nil, fmt.Errorf("the padding %d is too large for block size %d", nPad, blockSize)
	}

	for i := 2; i <= nPad; i++ {
		curPad := int(input[len(input)-i])
		if curPad != nPad {
			return nil, fmt.Errorf("invalid padding at position %d: got %d, expected %d", i, curPad, nPad)
		}
	}

	return input[:len(input)-nPad], nil
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

func AesEcbDecrypt(ciphertext []byte, key []byte) ([]byte, error) {
	cipher, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}

	res := make([]byte, len(ciphertext))
	for i := 0; i < len(res); i += AesBlockSize {
		cipher.Decrypt(res[i:i+AesBlockSize], ciphertext[i:i+AesBlockSize])
	}
	return PKCS7Unpad(res, AesBlockSize)
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

func ParseKV(s string) (map[string]string, error) {
	res := make(map[string]string)
	hasMoreKV := true
	for hasMoreKV {
		kv := s
		hasMoreKV = false
		if ampPos := strings.Index(s, "&"); ampPos >= 0 {
			kv = s[:ampPos]
			s = s[ampPos+1:]
			hasMoreKV = true
		}

		if eqPos := strings.Index(kv, "="); eqPos >= 0 {
			key, value := kv[:eqPos], kv[eqPos+1:]
			res[key] = value
		} else {
			return nil, fmt.Errorf("<%s> is not a valid key/value pair", kv)
		}
	}
	return res, nil
}
