package mt

func Temper(x uint32) uint32 {
	x ^= x >> 11
	x ^= (x << 7) & 0x9D2C5680
	x ^= (x << 15) & 0xEFC60000
	x ^= x >> 18
	return x
}

func Untemper(x uint32) uint32 {
	x ^= x >> 18
	x ^= (x << 15) & 0xEFC60000
	x ^= (x << 7) & 0x1680
	x ^= (x << 7) & 0xC4000
	x ^= (x << 7) & 0xD200000
	x ^= (x << 7) & 0x90000000
	x ^= (x >> 11) & 0xFFC00000
	x ^= (x >> 11) & 0x3FF800
	x ^= (x >> 11) & 0x7FF
	return x
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
