// Package spn implements a cryptanalysis of generic SPN block ciphers with 128-bit blocks and 8-bit S-boxes. See
// constructions/spn for more information on the construction itself.
//
// It is based on Biryukov's multiset calculus. The main techniques are Cube Attacks (Dinur) and Low Rank Detection
// (Biham).
//
// Cube attacks set up scenarios where the internal state of different instantiations of the cipher will sum to zero and
// leverage the knowledge of this to split the cryptosystem at the point where this happens. Cube attacks are used for
// splitting trailing S-box layers off of the body of the SPN.
//
// Low Rank Detection takes a set of ciphertexts and looks at them as a linear subspace. If the linear subspace they
// form has unusually small dimension, then we know that the corresponding plaintexts have caused collisions in the
// cipher's internal state. We can then separate what has collided from what hasn't. Low Rank Detection is used for
// removing trailing affine layers from the body of the SPN.
//
// "Structural Cryptanalysis of SASAS" by Alex Biryukov and Adi Shamir,
// https://www.iacr.org/archive/eurocrypt2001/20450392.pdf
//
// "Cryptanalysis of Patarin's 2-Round Public Key System with S-boxes (2R)" by E. Biham,
// http://www.iacr.org/archive/eurocrypt2000/1807/18070414-new.pdf
//
// "Cube Attacks on Tweakable Black Box Polynomials" by Itai Dinur and Adi Shamir,
// https://eprint.iacr.org/2008/385.pdf
package spn

import (
	"github.com/OpenWhiteBox/primitives/encoding"

	"github.com/OpenWhiteBox/Generic/constructions/spn"
)

// Construction represents an implementation of an SPN block cipher. The implementation doesn't assume that this is a
// constructions/spn.Construction for generality, and the cryptanalysis doesn't assume that you have access to Encrypt
// AND Decrypt--access to either allows you to break it.
type Construction interface {
	Encrypt([]byte, []byte)
}

// Encoding implements encoding.Block over a Construction to make some code simpler. Decode can not be called.
type Encoding struct{ Construction }

func (e Encoding) Encode(in [16]byte) (out [16]byte) {
	e.Construction.Encrypt(out[:], in[:])
	return
}

func (e Encoding) Decode(in [16]byte) (out [16]byte) {
	panic("cryptanalysis/spn.Encoding.Decode should never be called!")
}

// DecomposeSPN takes a Construction with a specified structure as input and outputs a functionally identical
// constructions/spn.Construction, with which you can Encrypt, Decrypt, inspect internal constants, etc.
func DecomposeSPN(constr Construction, structure spn.Structure) (out spn.Construction) {
	cipher := Encoding{constr}
	return decomposeSPN(cipher, structure)
}

func decomposeSPN(cipher encoding.Block, structure spn.Structure) (out spn.Construction) {
	switch structure {
	case spn.AS:
		last, rest := RecoverAffine(cipher, trivialSubspaces)
		first := encoding.DecomposeConcatenatedBlock(rest)
		return spn.Construction(encoding.ComposedBlocks{first, last})
	case spn.SA:
		last, rest := RecoverSBoxes(cipher, BalancedPlaintexts(4))
		first, _ := encoding.DecomposeBlockAffine(rest)
		return spn.Construction(encoding.ComposedBlocks{first, last})
	case spn.ASA:
		last, rest := RecoverAffine(cipher, lowRankDetectionWith(nextByAddition))
		return append(decomposeSPN(rest, spn.SA), last)
	case spn.SAS:
		last, rest := RecoverSBoxes(cipher, DualPlaintexts(4))
		return append(decomposeSPN(rest, spn.AS), last)
	case spn.ASAS:
		last, rest := RecoverAffine(cipher, lowRankDetectionWith(nextByToggle))
		return append(decomposeSPN(rest, spn.SAS), last)
	case spn.SASA:
		last, rest := RecoverSBoxes(cipher, PermutationPlaintexts(256))
		return append(decomposeSPN(rest, spn.ASA), last)
	// case spn.ASASA:
	case spn.SASAS:
		last, rest := RecoverSBoxes(cipher, PermutationPlaintexts(256))
		return append(decomposeSPN(rest, spn.ASAS), last)
	default:
		panic("Unknown SPN structure!")
	}
}
