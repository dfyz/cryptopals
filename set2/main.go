package main

import (
	"bytes"
	"crypto/aes"
	cryptoRand "crypto/rand"
	"cryptopals/util"
	"fmt"
	"log"
	"math/rand"
)

func Solve9() {
	orig := "YELLOW SUBMARINE"
	padded := util.PKCS7Pad([]byte(orig), 20)
	fmt.Printf("Challenge 9: %q\n", padded)
}

func Solve10() {
	content, err := util.ReadBase64File("10.txt")
	if err != nil {
		log.Fatal(err)
	}
	key := []byte("YELLOW SUBMARINE")
	iv := make([]byte, util.AesBlockSize)
	decoded, err := util.AesCbcDecrypt(content, key, iv)
	if err != nil {
		log.Fatal(err)
	}
	fmt.Printf("Challenge 10: %q\n", decoded)
}

func Solve11() {
	randBytes := func(n int) []byte {
		res := make([]byte, n)
		_, err := cryptoRand.Read(res)
		if err != nil {
			log.Fatalf("Failed to generated %d random bytes: %v", n, err)
		}
		return res
	}

	ecbCbcOracle := func(plaintext []byte) (res []byte, isCbc bool) {
		prefix := randBytes(5 + rand.Intn(6))
		suffix := randBytes(5 + rand.Intn(6))
		extended := append(append(prefix, plaintext...), suffix...)
		key := randBytes(util.AesBlockSize)
		if rand.Intn(2) == 1 {
			// CBC
			iv := randBytes(util.AesBlockSize)
			res, err := util.AesCbcEncrypt(extended, key, iv)
			if err != nil {
				log.Fatalf("Failed to encrypt under CBC: %v", err)
			}
			return res, true
		} else {
			// ECB
			padded := util.PKCS7Pad(extended, util.AesBlockSize)
			res := make([]byte, len(padded))
			cipher, err := aes.NewCipher(key)
			if err != nil {
				log.Fatalf("Failed to create a cipher for AES-ECB: %v", err)
			}
			for i := 0; i < len(res); i += util.AesBlockSize {
				cipher.Encrypt(res[i:i+util.AesBlockSize], padded[i:i+util.AesBlockSize])
			}
			return res, false
		}
	}

	guessIsCbc := func() bool {
		payload := bytes.Repeat([]byte("A"), aes.BlockSize*3)
		encrypted, oracleIsCbc := ecbCbcOracle(payload)
		guessedIsCbc := true
		for i := 0; i+2*util.AesBlockSize <= len(encrypted); i++ {
			slice1 := encrypted[i : i+util.AesBlockSize]
			slice2 := encrypted[i+util.AesBlockSize : i+2*util.AesBlockSize]
			if bytes.Equal(slice1, slice2) {
				guessedIsCbc = false
			}
		}
		return oracleIsCbc == guessedIsCbc
	}

	const attempts = 1000
	guessed := 0
	for i := 0; i < attempts; i++ {
		if guessIsCbc() {
			guessed++
		}
	}

	fmt.Printf("Challenge 11: guessed %d times out of %d\n", guessed, attempts)
}

func main() {
	Solve9()
	Solve10()
	Solve11()
}
