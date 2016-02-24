package spn

import (
	"crypto/rand"

	"github.com/OpenWhiteBox/primitives/encoding"
)

type Generator func() [][16]byte

// BalancedPlaintexts returns a generator for balanced sets of n plaintexts. Balanced, meaning the plaintexts sum to
// zero.
func BalancedPlaintexts(n int) Generator {
	return func() (out [][16]byte) {
		master := [16]byte{}

		for i := 0; i < n-1; i++ {
			pt := [16]byte{}
			rand.Read(pt[:])

			encoding.XOR(master[:], master[:], pt[:])

			out = append(out, pt)
		}

		out = append(out, master)

		return
	}
}

// DualPlaintexts returns a generator for dual sets of n plaintexts. Dual, meaning that the i^th position of the
// plaintexts either takes every value once or some subset of values an even number of times each.
func DualPlaintexts(n int) Generator {
	return func() (out [][16]byte) {
		for i := 0; i < n/2; i++ {
			pt := [16]byte{}
			rand.Read(pt[:])

			out = append(out, pt)
		}

		for i := n / 2; i < n; i++ {
			pt := [16]byte{}

			for pos := 0; pos < 16; pos++ {
				j := (pos + i) % (n / 2)
				pt[pos] = out[j][pos]
			}

			out = append(out, pt)
		}

		return out
	}
}

// PermutationPlaintexts returns a generator for sets of n plaintexts which are constant at all except one randomly
// chosen position, which takes as many values as possible.
func PermutationPlaintexts(n int) Generator {
	return func() (out [][16]byte) {
		master := [16]byte{}
		rand.Read(master[:])

		for i := 0; i < n; i++ {
			pt := [16]byte{}
			pt[master[0]&0x0f] = byte(i)

			encoding.XOR(pt[:], pt[:], master[:])

			out = append(out, pt)
		}

		return out
	}
}
