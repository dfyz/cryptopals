package main

import (
	"bytes"
	"crypto/aes"
	"cryptopals/util"
	"fmt"
	"log"
	"math"
	"math/rand"
	"strings"
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

func hasRepeatedBlock(input []byte) bool {
	const a = util.AesBlockSize
	for ii := 0; ii+2*a <= len(input); ii += a {
		for jj := ii + a; jj+a <= len(input); jj += a {
			matches := true
			for k := 0; matches && k < a; k++ {
				matches = matches && (input[ii+k] == input[jj+k])
			}
			if matches {
				return true
			}
		}
	}
	return false
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

	fmt.Printf("Challenge 12: %q\n", knownPlaintext)
}

func Solve13() {
	userId := 0
	profileFor := func(email string) string {
		if strings.ContainsAny(email, "&=") {
			log.Fatalf("<%s> is not a valid email", email)
		}
		userId++
		return fmt.Sprintf("email=%s&uid=%d&role=user", email, userId)
	}

	key := util.RandBytes(util.AesBlockSize)

	encryptProfile := func(email string) []byte {
		res, err := util.AesEcbEncrypt([]byte(profileFor(email)), key)
		if err != nil {
			log.Fatalf("Failed to encrypt profile for e-mail <%s>: <%v>", email, err)
		}
		return res
	}

	decryptProfile := func(encrypted []byte) map[string]string {
		rawProfile, err := util.AesEcbDecrypt(encrypted, key)
		if err != nil {
			log.Fatalf("Failed to decrypt profile <%v>: <%v>", encrypted, err)
		}

		res, err := util.ParseKV(string(rawProfile))
		if err != nil {
			log.Fatalf("Failed to parse decrypted profile <%v>: <%v>", rawProfile, err)
		}
		return res
	}

	profile1 := encryptProfile("AAAAAAAAAAAAAA")
	evil1 := profile1[:2*util.AesBlockSize]
	profile2 := encryptProfile("AAAAAAAAAAAAAAAAAAAAAAAAAAadmin")
	evil2 := profile2[2*util.AesBlockSize : len(profile2)-util.AesBlockSize]
	evil3 := profile2[:util.AesBlockSize]
	evil4 := profile1[len(profile1)-util.AesBlockSize:]
	evil := bytes.Join([][]byte{
		evil1, evil2, evil3, evil4,
	}, []byte(""))
	decrypted := decryptProfile(evil)

	isAdminRole := func(profile map[string]string) bool {
		value, ok := profile["role"]
		return ok && value == "admin"
	}
	fmt.Printf("Challenge 13: isAdminRole(%v) = %v\n", decrypted, isAdminRole(decrypted))
}

func Solve14() {
	key := util.RandBytes(util.AesBlockSize)
	secret, err := util.ReadBase64File("12.txt")
	if err != nil {
		log.Fatal(err)
	}

	oracle := func(payload []byte) []byte {
		// Note that the challenge description is ambiguous: it is not clear if the oracle should
		// generate the prefix upfront (similar to the AES key), or re-generate the prefix every
		// time the oracle is called.
		//
		// My solution is for the latter version, which is harder to attack.
		prefix := util.RandBytes(rand.Intn(42))
		plaintext := append(prefix, append(payload, secret...)...)
		encrypted, err := util.AesEcbEncrypt(plaintext, key)
		if err != nil {
			log.Fatalf("Failed to encrypt <%v>: %v", payload, err)
		}
		return encrypted
	}

	guessChar := func(known []byte) byte {
		nextLen := len(known) + 1

		padLen := 0
		if nextLen%util.AesBlockSize != 0 {
			padLen = util.AesBlockSize - nextLen%util.AesBlockSize
		}
		pad := make([]byte, padLen)

		suffix := append(pad, append(known, byte(0))...)
		payload := append(suffix[len(suffix)-util.AesBlockSize:], pad...)

		cands := make([]byte, math.MaxUint8)
		for {
			for b := 0; b < math.MaxUint8; b++ {
				bb := byte(b)
				payload[util.AesBlockSize-1] = bb
				encrypted := oracle(payload)
				if hasRepeatedBlock(encrypted) {
					cands[bb]++
					if cands[bb] > 2 {
						return bb
					}
				}
			}
		}
	}

	knownPlaintext := make([]byte, 0)
	for {
		guessed := guessChar(knownPlaintext)
		if guessed == 1 {
			break
		}
		knownPlaintext = append(knownPlaintext, guessed)
	}
	fmt.Printf("Challenge 14: %q\n", knownPlaintext)
}

func Solve15() {
	isValidPadding := func(input []byte) bool {
		_, err := util.PKCS7Unpad(input, aes.BlockSize)
		return err == nil
	}

	valid := []byte("ICE ICE BABY\x04\x04\x04\x04")
	invalid1 := []byte("ICE ICE BABY\x05\x05\x05\x05")
	invalid2 := []byte("ICE ICE BABY\x01\x02\x03\x04")

	fmt.Printf(
		"Challenge 15: valid(%q) = %v, valid(%q) = %v, valid(%q) = %v\n",
		valid,
		isValidPadding(valid),
		invalid1,
		isValidPadding(invalid1),
		invalid2,
		isValidPadding(invalid2),
	)
}

func Solve16() {
	key := util.RandBytes(util.AesBlockSize)

	encrypt := func(payload []byte) (ciphertext []byte, iv []byte) {
		if bytes.ContainsAny(payload, ";=") {
			log.Fatalf("Payload %q contains forbidden characters", payload)
		}
		prefix := []byte("comment1=cooking%20MCs;userdata=")
		suffix := []byte(";comment2=%20like%20a%20pound%20of%20bacon")
		plaintext := append(prefix, append(payload, suffix...)...)
		localIv := util.RandBytes(util.AesBlockSize)
		res, err := util.AesCbcEncrypt(plaintext, key, localIv)
		if err != nil {
			log.Fatalf("Failed to encrypt %q: %v", payload, err)
		}
		return res, localIv
	}

	isAdmin := func(ciphertext []byte, iv []byte) bool {
		decrypted, err := util.AesCbcDecrypt(ciphertext, key, iv)
		if err != nil {
			log.Fatalf("Failed to decrypt %q: %v", ciphertext, err)
		}
		fmt.Printf("%q\n", decrypted)
		return bytes.Contains(decrypted, []byte(";admin=true;"))
	}

	payload := append(
		bytes.Repeat([]byte("A"), util.AesBlockSize), // We will flip bits in this block...
		[]byte("?admin?true?")...,                    // ...in order to change this one.
	)
	ciphertext, iv := encrypt(payload)

	bitFlip := func(byteIdx int, bitIdx int) {
		ciphertext[byteIdx] = ciphertext[byteIdx] ^ (1 << bitIdx)
	}

	// The 2nd (0-indexed) block contains the block we want to mess with
	start := 2 * util.AesBlockSize

	//        7 6 5 4 3  2   1  0
	// '?' is 0 0 1 1 1  1   1  1
	// ';' is 0 0 1 1 1 [0]  1  1
	// '=' is 0 0 1 1 1  1  [0] 1

	// v              v
	// ?admin?true? → ;admin?true?
	bitFlip(start, 2)
	//       v              v
	// ;admin?true? → ;admin=true?
	bitFlip(start+6, 1)
	//            v              v
	// ;admin=true? → ;admin=true;
	bitFlip(start+11, 2)

	fmt.Printf("Challenge 16: isAdmin = %v\n", isAdmin(ciphertext, iv))
}

func main() {
	Solve9()
	Solve10()
	Solve11()
	Solve12()
	Solve13()
	Solve14()
	Solve15()
	Solve16()
}
