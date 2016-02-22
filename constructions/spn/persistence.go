package spn

import (
	"github.com/OpenWhiteBox/primitives/encoding"
	"github.com/OpenWhiteBox/primitives/matrix"
)

// Serialize serializes an SPN construction into a byte slice.
func (constr *Construction) Serialize() (out []byte) {
	for _, layer := range *constr {
		switch layer := layer.(type) {
		case encoding.ConcatenatedBlock:
			for pos := 0; pos < 16; pos++ {
				out = append(out, encoding.SerializeByte(layer[pos])...)
			}

		case encoding.BlockAffine:
			for _, row := range layer.BlockLinear.Forwards {
				out = append(out, row...)
			}
			out = append(out, layer.BlockAdditive[:]...)
		}
	}

	return
}

func parseSBoxLayer(constr *Construction, in *[]byte) {
	sbox := encoding.ConcatenatedBlock{}
	rest := (*in)[:]

	for pos := 0; pos < 16; pos++ {
		sbox[pos], rest = encoding.ParseByte(rest[0:256]), rest[256:]
	}

	*constr = append(*constr, sbox)
	*in = rest
}

func parseAffineLayer(constr *Construction, in *[]byte) {
	linear := matrix.Matrix{}
	rest := (*in)[:]

	for row := 0; row < 128; row++ {
		linear, rest = append(linear, matrix.Row(rest[0:16])), rest[16:]
	}

	constant := [16]byte{}
	copy(constant[:], rest[0:16])

	*constr = append(*constr, encoding.NewBlockAffine(linear, constant))
	*in = rest[16:]
}

// Parse parses a byte array into an SPN construction with the specificed structure. It panics if the byte array is
// malformed.
func Parse(in []byte, structure Structure) (constr Construction) {
	rest := in[:]

	switch structure {
	case AS:
		parseSBoxLayer(&constr, &rest)
		parseAffineLayer(&constr, &rest)
	case SA:
		parseAffineLayer(&constr, &rest)
		parseSBoxLayer(&constr, &rest)
	case ASA:
		parseAffineLayer(&constr, &rest)
		parseSBoxLayer(&constr, &rest)
		parseAffineLayer(&constr, &rest)
	case SAS:
		parseSBoxLayer(&constr, &rest)
		parseAffineLayer(&constr, &rest)
		parseSBoxLayer(&constr, &rest)
	case SASA:
		parseAffineLayer(&constr, &rest)
		parseSBoxLayer(&constr, &rest)
		parseAffineLayer(&constr, &rest)
		parseSBoxLayer(&constr, &rest)
	case ASAS:
		parseSBoxLayer(&constr, &rest)
		parseAffineLayer(&constr, &rest)
		parseSBoxLayer(&constr, &rest)
		parseAffineLayer(&constr, &rest)
	case SASAS:
		parseSBoxLayer(&constr, &rest)
		parseAffineLayer(&constr, &rest)
		parseSBoxLayer(&constr, &rest)
		parseAffineLayer(&constr, &rest)
		parseSBoxLayer(&constr, &rest)
	default:
		panic("Unknown SPN structure!")
	}

	return
}
