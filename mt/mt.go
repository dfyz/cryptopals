package mt

import (
	"encoding/binary"
	"math/bits"
)

func Temper(x uint32) uint32 {
	x ^= x >> 11
	x ^= (x << 7) & 0x9D2C5680
	x ^= (x << 15) & 0xEFC60000
	x ^= x >> 18
	return x
}

func Untemper(x uint32) uint32 {
	invMat := []uint32{
		0x22440881,
		0x44081122,
		0x89022200,
		0x10244489,
		0x64c89830,
		0x48911020,
		0x133640c5,
		0x2204889,
		0x4889120,
		0x81130000,
		0x12044489,
		0x22400880,
		0x44001120,
		0x89122204,
		0x10044481,
		0x64889820,
		0x48111000,
		0x12364085,
		0x244808,
		0x889020,
		0x89030204,
		0x2244081,
		0x2400080,
		0x4800100,
		0x9120204,
		0x12000400,
		0x64881820,
		0x48101000,
		0x12244081,
		0x20004000,
		0x40008000,
		0x89130204,
	}

	res := uint32(0)
	for bit := 0; bit < 32; bit++ {
		if bits.OnesCount32(x&invMat[bit])%2 == 1 {
			res |= 1 << bit
		}
	}
	return res
}

const N = 624

type Mt19937 struct {
	state [N]uint32
}

func New(seed uint32) Mt19937 {
	res := Mt19937{}
	res.state[0] = seed
	for i := 1; i < len(res.state); i++ {
		prev := res.state[i-1]
		res.state[i] = 1812433253*(prev^(prev>>30)) + uint32(i)
	}
	return res
}

func Clone(state []uint32) Mt19937 {
	res := Mt19937{}
	copy(res.state[:], state)
	return res
}

func (mt *Mt19937) Next() uint32 {
	next := mt.state[1]
	if mt.state[0]&(1<<31) != 0 {
		next |= 1 << 31
	} else {
		next &= ^(uint32(1 << 31))
	}
	xorA := next&1 != 0
	next >>= 1
	if xorA {
		next ^= 0x9908B0DF
	}
	next ^= mt.state[397]

	copy(mt.state[0:], mt.state[1:])
	mt.state[len(mt.state)-1] = next
	return Temper(next)
}

func Crypt(payload []byte, seed uint32) []byte {
	rng := New(seed)
	res := make([]byte, len(payload))
	for ii := 0; ii < len(res); ii += 4 {
		keystream := make([]byte, 4)
		binary.LittleEndian.PutUint32(keystream, rng.Next())
		for jj := 0; jj < 4 && ii+jj < len(res); jj++ {
			res[ii+jj] = payload[ii+jj] ^ keystream[jj]
		}
	}
	return res
}
