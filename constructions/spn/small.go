package spn

import (
	"io"

	"github.com/OpenWhiteBox/primitives/encoding"
	"github.com/OpenWhiteBox/primitives/matrix"
)

func newSmallAffineLayer(rand io.Reader) encoding.ByteAffine {
	c := [1]byte{}
	rand.Read(c[:])

	return encoding.NewByteAffine(matrix.GenerateRandom(rand, 8), c[0])
}

func newSmallSBoxLayer(rand io.Reader) encoding.ConcatenatedByte {
	return encoding.ConcatenatedByte{
		encoding.GenerateShuffle(rand),
		encoding.GenerateShuffle(rand),
	}
}

// NewSPN generates a random SPN instance using the random source random (for example, crypto/rand.Reader), with the
// specified structure.
func NewSmallSPN(rand io.Reader, structure Structure) encoding.Byte {
	switch structure {
	case AS:
		return encoding.ComposedBytes{
			newSmallSBoxLayer(rand), newSmallAffineLayer(rand),
		}
	case SA:
		return encoding.ComposedBytes{
			newSmallAffineLayer(rand), newSmallSBoxLayer(rand),
		}
	case ASA:
		return encoding.ComposedBytes{
			newSmallAffineLayer(rand), newSmallSBoxLayer(rand), newSmallAffineLayer(rand),
		}
	case SAS:
		return encoding.ComposedBytes{
			newSmallSBoxLayer(rand), newSmallAffineLayer(rand), newSmallSBoxLayer(rand),
		}
	case ASAS:
		return encoding.ComposedBytes{
			newSmallSBoxLayer(rand), newSmallAffineLayer(rand), newSmallSBoxLayer(rand), newSmallAffineLayer(rand),
		}
	case SASA:
		return encoding.ComposedBytes{
			newSmallAffineLayer(rand), newSmallSBoxLayer(rand), newSmallAffineLayer(rand), newSmallSBoxLayer(rand),
		}
	case ASASA:
		return encoding.ComposedBytes{
			newSmallAffineLayer(rand), newSmallSBoxLayer(rand), newSmallAffineLayer(rand), newSmallSBoxLayer(rand), newSmallAffineLayer(rand),
		}
	case SASAS:
		return encoding.ComposedBytes{
			newSmallSBoxLayer(rand), newSmallAffineLayer(rand), newSmallSBoxLayer(rand), newSmallAffineLayer(rand), newSmallSBoxLayer(rand),
		}
	default:
		panic("Unknown SPN structure!")
	}
}
