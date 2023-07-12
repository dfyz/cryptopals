package main

import (
	"cryptopals/util"
	"fmt"
	"log"
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

func main() {
	Solve9()
	Solve10()
}
