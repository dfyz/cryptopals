package main

import (
	"bytes"
	"crypto/aes"
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
	ecbCbcOracle := func(plaintext []byte) (res []byte, isCbc bool) {
		prefix := util.RandBytes(5 + rand.Intn(6))
		suffix := util.RandBytes(5 + rand.Intn(6))
		extended := append(append(prefix, plaintext...), suffix...)
		key := util.RandBytes(util.AesBlockSize)
		if rand.Intn(2) == 1 {
			// CBC
			iv := util.RandBytes(util.AesBlockSize)
			res, err := util.AesCbcEncrypt(extended, key, iv)
			if err != nil {
				log.Fatalf("Failed to encrypt under CBC: %v", err)
			}
			return res, true
		} else {
			// ECB
			res, err := util.AesEcbEncrypt(extended, key)
			if err != nil {
				log.Fatalf("Failed to create a cipher for AES-ECB: %v", err)
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

func Solve12() {
	key := util.RandBytes(util.AesBlockSize)
	secret, err := util.ReadBase64File("12.txt")
	if err != nil {
		log.Fatal(err)
	}

	oracle := func(payload []byte) []byte {
		plaintext := append(payload, secret...)
		encrypted, err := util.AesEcbEncrypt(plaintext, key)
		if err != nil {
			log.Fatalf("Failed to encrypt <%v>: %v", payload, err)
		}
		return encrypted
	}

	paddingBytes := 0
	rep := func(n int) []byte {
		return bytes.Repeat([]byte("A"), n)
	}
	secretLen := len(oracle(rep(0)))
	for {
		paddingBytes++
		if secretLen != len(oracle(rep(paddingBytes))) {
			break
		}
	}
	secretLen -= paddingBytes

	const a = util.AesBlockSize
	type Block = [a]byte
	knownPlaintext := make([]byte, 0)
	for y := 0; y < secretLen; y++ {
		x := ((-(y + 1) % a) + a) % a
		prefix := append(rep(x), knownPlaintext...)
		codebook := make(map[Block]byte)
		lastBlock := prefix[len(prefix)-(a-1):]
		for b := 0; b < 256; b++ {
			payload := append(lastBlock, byte(b))
			key := Block(oracle(payload)[:a])
			codebook[key] = byte(b)
		}

		encrypted := oracle(rep(x))
		targetStart := len(prefix) - (a - 1)
		target := Block(encrypted[targetStart : targetStart+a])
		restored, ok := codebook[target]
		if !ok {
			log.Fatalf("Failed to restore byte %d", y)
		}
		knownPlaintext = append(knownPlaintext, restored)
	}

	fmt.Printf("Challenge 12: %q", knownPlaintext)
}

func main() {
	Solve9()
	Solve10()
	Solve11()
	Solve12()
}
