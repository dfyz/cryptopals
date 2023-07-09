package main

import (
	"crypto/aes"
	"encoding/base64"
	"encoding/hex"
	"fmt"
	"io/ioutil"
	"log"
	"math"
	"strings"
)

func Check(err error) {
	if err != nil {
		log.Fatal(err)
	}
}

func Xor(source []byte, key []byte) []byte {
	result := make([]byte, len(source))
	copy(result, source)
	keyIdx := 0
	for i, _ := range result {
		result[i] = source[i] ^ key[keyIdx]
		keyIdx = (keyIdx + 1) % len(key)
	}
	return result
}

type Histogram map[byte]int

func CreateHistogram(source []byte) Histogram {
	result := make(Histogram)
	for _, b := range source {
		result[b]++
	}
	return result
}

func HistogramDistance(a Histogram, b Histogram) float64 {
	result := 0
	for i := 0; i <= math.MaxUint8; i++ {
		delta := a[byte(i)] - b[byte(i)]
		result += delta * delta
	}
	return math.Sqrt(float64(result))
}

func CreateModelHistogram() Histogram {
	model := []byte(`This is a different way to learn about crypto than taking a class or reading a book. We give you problems to solve. They're derived from weaknesses in real-world systems and modern cryptographic constructions. We give you enough info to learn about the underlying crypto concepts yourself. When you're finished, you'll not only have learned a good deal about how cryptosystems are built, but you'll also understand how they're attacked.`)
	return CreateHistogram(model)
}

var modelHistogram Histogram = CreateModelHistogram()

func Readability(candidate string) float64 {
	return HistogramDistance(modelHistogram, CreateHistogram([]byte(candidate)))
}

func SolveSingleCharacterXorString(hexStr string) (bestAnswer string, bestKey int, bestReadability float64) {
	rawStr, err := hex.DecodeString(hexStr)
	Check(err)
	return SolveSingleCharacterXor(rawStr)
}

func SolveSingleCharacterXor(rawStr []byte) (bestAnswer string, bestKey int, bestReadability float64) {
	bestReadability = math.Inf(1)
	for key := 0; key <= math.MaxUint8; key++ {
		candidate := string(Xor(rawStr, []byte{byte(key)}))
		readability := Readability(candidate)
		if readability < bestReadability {
			bestAnswer = candidate
			bestKey = key
			bestReadability = readability
		}
	}
	return
}

func Solve1() {
	rawStr, err := hex.DecodeString("49276d206b696c6c696e6720796f757220627261696e206c696b65206120706f69736f6e6f7573206d757368726f6f6d")
	Check(err)
	fmt.Printf("Challenge 1: %s\n", base64.StdEncoding.EncodeToString(rawStr))
}

func Solve2() {
	str1, err := hex.DecodeString("1c0111001f010100061a024b53535009181c")
	Check(err)
	str2, err := hex.DecodeString("686974207468652062756c6c277320657965")
	Check(err)
	fmt.Printf("Challenge 2: %s\n", hex.EncodeToString(Xor(str1, str2)))
}

func Solve3() {
	hexStr := "1b37373331363f78151b7f2b783431333d78397828372d363c78373e783a393b3736"
	bestAnswer, bestKey, bestReadability := SolveSingleCharacterXorString(hexStr)
	fmt.Printf("Challenge 3: decoded with key %d: <%s> (READABILITY = %g)\n", bestKey, bestAnswer, bestReadability)
}

func Solve4() {
	content, err := ioutil.ReadFile("4.txt")
	Check(err)
	lines := strings.Split(string(content), "\n")
	globalBestAnswer, globalBestReadability, globalBestKey, bestLine := "", math.Inf(1), 0, ""
	for _, line := range lines {
		bestAnswer, bestKey, bestReadability := SolveSingleCharacterXorString(line)
		if bestReadability < globalBestReadability {
			globalBestAnswer, globalBestReadability, globalBestKey = bestAnswer, bestReadability, bestKey
			bestLine = line
		}
	}
	globalBestAnswer = strings.TrimSpace(globalBestAnswer)
	fmt.Printf("Challenge 4: decoded %s with key %d: <%s> (READABILITY = %g)\n", bestLine, globalBestKey, globalBestAnswer, globalBestReadability)
}

func Solve5() {
	str := `Burning 'em, if you ain't quick and nimble I go crazy when I hear a cymbal`
	xored := Xor([]byte(str), []byte("ICE"))
	fmt.Printf("Challenge 5: %s\n", hex.EncodeToString(xored))
}

func Solve6() {
	content, err := ioutil.ReadFile("6.txt")
	Check(err)
	rawStr, err := base64.StdEncoding.DecodeString(string(content))
	Check(err)

	bestSimilarity, bestKeyLen := 0, 0
	for keyLen := 2; keyLen <= 100; keyLen++ {
		similarity := 0
		for i := 0; i+keyLen < len(rawStr); i++ {
			if rawStr[i] == rawStr[i+keyLen] {
				similarity++
			}
		}
		if similarity > bestSimilarity {
			bestSimilarity = similarity
			bestKeyLen = keyLen
		}
	}

	key := []byte{}
	for i := 0; i < bestKeyLen; i++ {
		substr := make([]byte, 0, len(rawStr))
		for j := i; j < len(rawStr); j += bestKeyLen {
			substr = append(substr, rawStr[j])
		}
		_, bestKey, _ := SolveSingleCharacterXor(substr)
		key = append(key, byte(bestKey))
	}
	fmt.Printf("Challenge 6: key = %s\n", string(key))
}

func Solve7() {
	content, err := ioutil.ReadFile("7.txt")
	Check(err)
	cipherText, err := base64.StdEncoding.DecodeString(string(content))
	Check(err)
	block, err := aes.NewCipher([]byte("YELLOW SUBMARINE"))
	Check(err)

	result := ""
	buffer := make([]byte, aes.BlockSize)
	for i := 0; i < len(cipherText); i += aes.BlockSize {
		block.Decrypt(buffer, cipherText[i:i+aes.BlockSize])
		result += string(buffer)
	}
	lines := strings.Split(result, "\n")
	fmt.Printf(
		"Challenge 7: first line = <%s>, last line = <%s>\n",
		strings.TrimSpace(lines[0]), strings.TrimSpace(lines[len(lines)-2]),
	)
}

func Solve8() {
	content, err := ioutil.ReadFile("8.txt")
	Check(err)
	lines := strings.Split(string(content), "\n")
	for _, line := range lines {
		if len(line) == 0 {
			continue
		}
		rawLine, err := hex.DecodeString(line)
		Check(err)
		blocks := make(map[string]int)
		const blockSize = 16
		for j := 0; j < len(rawLine); j += blockSize {
			blocks[string(rawLine[j:j+blockSize])]++
		}
		if len(blocks) < len(rawLine)/blockSize {
			fmt.Printf("Challenge 8: %s: %d unique blocks\n", line, len(blocks))
		}
	}
}

func main() {
	Solve1()
	Solve2()
	Solve3()
	Solve4()
	Solve5()
	Solve6()
	Solve7()
	Solve8()
}
