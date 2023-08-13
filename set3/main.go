package main

import (
	"bytes"
	"cryptopals/mt"
	"cryptopals/util"
	"fmt"
	"math/rand"
	"time"
)

func Solve21() {
	fmt.Printf("Challenge 21: is just the implementation of Mersenne Twister in mt/mt.go\n")
}

func Solve22() {
	curTime := uint32(time.Now().Unix())

	getDelta := func() uint32 {
		min, max := int32(40), int32(1000)
		return uint32(rand.Int31n(max-min) + min)
	}

	seed := curTime + getDelta()
	rng := mt.New(seed)
	rngOut := rng.Next()

	userTime := seed + getDelta()
	for delta := uint32(0); ; delta++ {
		candSeed := userTime - delta
		candMt := mt.New(candSeed)
		if candMt.Next() == rngOut {
			fmt.Printf("Challenge 22: original seed = %d, found seed = %d\n", seed, candSeed)
			break
		}
	}
}

func Solve23() {
	seed := rand.Uint32()
	rng := mt.New(seed)
	cloned := make([]uint32, mt.N)
	for i := 0; i < mt.N; i++ {
		cloned[i] = mt.Untemper(rng.Next())
	}

	fakeRng := mt.Clone(cloned)
	matches := 0
	for ii := 0; ii < 1000; ii++ {
		if rng.Next() == fakeRng.Next() {
			matches++
		}
	}
	fmt.Printf(
		"Challenge 23: the cloned RNG agrees with the real one for %d steps out of 1000\n",
		matches,
	)
}

func Solve24() {
	knownSuffix := bytes.Repeat([]byte("A"), 14)
	plaintext := append(util.RandBytes(rand.Intn(42)), knownSuffix...)
	seed16 := rand.Intn(1 << 16)
	ciphertext16 := mt.Crypt(plaintext, uint32(seed16))

	restoredSeed16 := uint32(0)
	for candSeed := uint32(0); candSeed < (1 << 16); candSeed++ {
		if bytes.HasSuffix(mt.Crypt(ciphertext16, candSeed), knownSuffix) {
			restoredSeed16 = candSeed
			break
		}
	}

	seedTime := uint32(time.Now().Unix())
	ciphertextTime := mt.Crypt(plaintext, seedTime)

	restoredSeedTime := uint32(0)
	curTime := uint32(time.Now().Unix())
	for delta := uint32(0); ; delta++ {
		candSeed := curTime - delta
		if bytes.HasSuffix(mt.Crypt(ciphertextTime, candSeed), knownSuffix) {
			restoredSeedTime = candSeed
			break
		}
	}

	fmt.Printf(
		"Challenge 24: 16-bit seed = %d/%d, timestamp seed = %d/%d\n",
		seed16,
		restoredSeed16,
		seedTime,
		restoredSeedTime,
	)
}

func main() {
	Solve21()
	Solve22()
	Solve23()
	Solve24()
}
