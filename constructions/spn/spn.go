// Package spn implements a generic SPN block ciphers with 128-bit blocks and 8-bit S-boxes.
//
// An affine layer, denoted by an A, treats its input as an element of GF(2)^n and applies a fixed, invertible affine
// transformation over this space. An S-box layer, denoted by an S, applies possibly independent 8-bit S-boxes to
// consecutive chunks of its input. The layers are concatenated as in function composition notation. A block cipher E
// with structure ASAS implies E = A(S(A(S(x)))).
//
// An efficient cryptanalysis of many of these block ciphers is implemented in the cryptanalysis/spn package.
//
// "Structural Cryptanalysis of SASAS" by Alex Biryukov and Adi Shamir,
// https://www.iacr.org/archive/eurocrypt2001/20450392.pdf
package spn

import (
	"github.com/OpenWhiteBox/primitives/encoding"
)

type Structure int

const (
	AS Structure = iota
	SA
	ASA
	SAS
	ASAS
	SASA
	ASASA
	SASAS
)

type Construction encoding.ComposedBlocks

// BlockSize returns the block size of the cipher. (Necessary to implement cipher.Block.)
func (constr Construction) BlockSize() int { return 16 }

// Encrypt encrypts the first block in src into dst. Dst and src may point at the same memory.
func (constr Construction) Encrypt(dst, src []byte) {
	temp := [16]byte{}
	copy(temp[:], src)

	temp = encoding.ComposedBlocks(constr).Encode(temp)

	copy(dst, temp[:])
}

// Decrypt decrypts the first block in src into dst. Dst and src may point at the same memory.
func (constr Construction) Decrypt(dst, src []byte) {
	temp := [16]byte{}
	copy(temp[:], src)

	temp = encoding.ComposedBlocks(constr).Decode(temp)

	copy(dst, temp[:])
}
