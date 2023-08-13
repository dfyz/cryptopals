package mt

import (
	"log"
	"testing"
)

func TestTemper(t *testing.T) {
	vals := []uint32{1, 1337, 31337, 1234567, 3_133_731_337}
	for _, orig := range vals {
		tempered := Temper(orig)
		if tempered == orig {
			log.Fatalf("Temper(%d) should change the value", orig)
		}
		restored := Untemper(tempered)
		if restored != orig {
			log.Fatalf("Untemper(Temper(%d)) = %d", orig, restored)
		}
	}
}

func TestMt19937(t *testing.T) {
	const N = 10
	tests := []struct {
		seed     uint32
		expected [N]uint32
	}{
		{
			31337,
			[N]uint32{
				3100331191,
				3480951327,
				4150831638,
				1400216829,
				1241456317,
				1281828199,
				735926457,
				1092721871,
				1596085388,
				264094031,
			},
		},
		{
			3_133_731_337,
			[N]uint32{
				3913149591,
				3484207552,
				2204713265,
				2447555934,
				2377731424,
				2054976647,
				1275341698,
				3546463029,
				4156584721,
				3146618038,
			},
		},
	}

	for _, tt := range tests {
		mt := New(tt.seed)
		for ii := 0; ii < N; ii++ {
			actual := mt.Next()
			if actual != tt.expected[ii] {
				log.Fatalf("seed %d, element #%d: %d != %d", tt.seed, ii, actual, tt.expected[ii])
			}
		}
	}
}
