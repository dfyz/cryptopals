package main

import (
	"cryptopals/mt"
	"fmt"
	"log"
	"math/rand"
	"time"
)

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
	for delta := uint32(0); true; delta++ {
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
	log.Printf(
		"Challenge 23: the cloned RNG agrees with the real one for %d steps out of 1000",
		matches,
	)
}

func main() {
	// Solve21() is the implementation of Mersenne Twister in mt/mt.go
	Solve22()
	Solve23()
}
