package main

import (
	"cryptopals/mt"
	"fmt"
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

func main() {
	// Solve21() is the implementation of Mersenne Twister in mt/mt.go
	Solve22()
}
