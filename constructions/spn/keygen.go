package spn

import (
	"io"

	"github.com/OpenWhiteBox/primitives/encoding"
	"github.com/OpenWhiteBox/primitives/matrix"
)

func newAffineLayer(rand io.Reader) encoding.BlockAffine {
	c := [16]byte{}
	rand.Read(c[:])

	return encoding.NewBlockAffine(matrix.GenerateRandom(rand, 128), c)
}

func newSBoxLayer(rand io.Reader) encoding.ConcatenatedBlock {
	sbox := encoding.ConcatenatedBlock{}
	for pos := 0; pos < 16; pos++ {
		sbox[pos] = encoding.GenerateSBox(rand)
	}

	return sbox
}

// NewSPN generates a random SPN instance using the random source random (for example, crypto/rand.Reader), with the
// specified structure.
func NewSPN(rand io.Reader, structure Structure) Construction {
	switch structure {
	case AS:
		return Construction(encoding.ComposedBlocks{
			newSBoxLayer(rand), newAffineLayer(rand),
		})
	case SA:
		return Construction(encoding.ComposedBlocks{
			newAffineLayer(rand), newSBoxLayer(rand),
		})
	case ASA:
		return Construction(encoding.ComposedBlocks{
			newAffineLayer(rand), newSBoxLayer(rand), newAffineLayer(rand),
		})
	case SAS:
		return Construction(encoding.ComposedBlocks{
			newSBoxLayer(rand), newAffineLayer(rand), newSBoxLayer(rand),
		})
	case SASA:
		return Construction(encoding.ComposedBlocks{
			newAffineLayer(rand), newSBoxLayer(rand), newAffineLayer(rand), newSBoxLayer(rand),
		})
	case ASAS:
		return Construction(encoding.ComposedBlocks{
			newSBoxLayer(rand), newAffineLayer(rand), newSBoxLayer(rand), newAffineLayer(rand),
		})
	case SASAS:
		return Construction(encoding.ComposedBlocks{
			newSBoxLayer(rand), newAffineLayer(rand), newSBoxLayer(rand), newAffineLayer(rand), newSBoxLayer(rand),
		})
	default:
		panic("Unknown SPN structure!")
	}
}
