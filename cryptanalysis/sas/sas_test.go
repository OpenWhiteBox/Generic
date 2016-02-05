package sas

import (
	"fmt"
	"testing"

	// "bytes"
	"crypto/rand"

	"github.com/OpenWhiteBox/primitives/encoding"
	"github.com/OpenWhiteBox/primitives/gfmatrix"
	"github.com/OpenWhiteBox/primitives/number"
	// "github.com/OpenWhiteBox/primitives/table"
	// "github.com/OpenWhiteBox/primitives/matrix"

	"github.com/OpenWhiteBox/Generic/constructions/sas"

	"github.com/OpenWhiteBox/AES/constructions/chow"
	"github.com/OpenWhiteBox/AES/constructions/common"
	"github.com/OpenWhiteBox/AES/constructions/saes"
)

func testAffine(cipher encoding.Block) bool {
	aff := encoding.DecomposeBlockAffine(cipher)
	return encoding.ProbablyEquivalentBlocks(cipher, aff)
}

type FirstEncoding struct {
	Construction saes.Construction
}

func (fe FirstEncoding) Encode(in [16]byte) (out [16]byte) {
	temp := make([]byte, 16)
	copy(temp, in[:])

	roundKeys := fe.Construction.StretchedKey()
	fe.Construction.ShiftRows(roundKeys[1])

	fe.Construction.AddRoundKey(roundKeys[1], temp)
	fe.Construction.SubBytes(temp)

	copy(out[:], temp)

	return
}

func (fe FirstEncoding) Decode(in [16]byte) (out [16]byte) {
	temp := make([]byte, 16)
	copy(temp, in[:])

	roundKeys := fe.Construction.StretchedKey()
	fe.Construction.ShiftRows(roundKeys[1])

	fe.Construction.UnSubBytes(temp)
	fe.Construction.AddRoundKey(roundKeys[1], temp)

	copy(out[:], temp)

	return
}

type ChowConstruction struct {
	Constr chow.Construction
	Round  int
}

func (cc ChowConstruction) Encrypt(dst, src []byte) {
	copy(dst[0:16], src[0:16])

	for pos := 0; pos < 16; pos += 4 {
		stretched := cc.Constr.ExpandWord(cc.Constr.TBoxTyiTable[cc.Round][pos:pos+4], dst[pos:pos+4])
		cc.Constr.SquashWords(cc.Constr.HighXORTable[cc.Round][2*pos:2*pos+8], stretched, dst[pos:pos+4])

		stretched = cc.Constr.ExpandWord(cc.Constr.MBInverseTable[cc.Round][pos:pos+4], dst[pos:pos+4])
		cc.Constr.SquashWords(cc.Constr.LowXORTable[cc.Round][2*pos:2*pos+8], stretched, dst[pos:pos+4])
	}
}

var noshift = func(position int) int { return position }

func TestDecomposeChow(t *testing.T) {
	key := make([]byte, 16)
	rand.Read(key)

	sConstr := saes.Construction{
		Key: key,
	}

	constr, _, _ := chow.GenerateEncryptionKeys(
		key, key, common.IndependentMasks{common.RandomMask, common.RandomMask},
	)

	fmt.Println("Construction generated")

	serialized := constr.Serialize()
	constr2, _ := chow.Parse(serialized)

	fmt.Println("Construction serialized")

	cipher := Encoding{
		ChowConstruction{
			Constr: constr2,
			Round:  1,
		},
	}

	firstEncoding := encoding.ConcatenatedBlock{}
	for i := 0; i < 16; i++ {
		firstEncoding[i] = constr.TBoxTyiTable[1][i].(encoding.WordTable).In
	}

	lastEncoding := encoding.ConcatenatedBlock{}
	for i := 0; i < 16; i++ {
		lastEncoding[i] = constr.TBoxTyiTable[2][common.ShiftRows(i)].(encoding.WordTable).In
	}

	first := encoding.ComposedBlocks{
		encoding.InverseBlock{firstEncoding},
		FirstEncoding{sConstr},
	}

	cipher2 := encoding.ComposedBlocks{
		encoding.InverseBlock{first},
		cipher,
		encoding.InverseBlock{lastEncoding},
	}

	constr3 := DecomposeSAS(cipher)

	// cipher3 := encoding.ComposedBlocks{
	// 	encoding.InverseBlock{first},
	// 	cipher,
	// 	encoding.InverseBlock{lastEncoding},
	// }

	MC := encoding.DecomposeBlockAffine(cipher2).BlockLinear.Forwards

	fmt.Println(constr3.Affine.BlockLinear.Forwards.OctaveString())

	rightParasite, _ := encoding.DecomposeBlockAffine(encoding.ComposedBlocks{
		encoding.InverseBlock{first},
		constr3.First,
	}).BlockLinear.Forwards.Invert()

	leftParasite, _ := encoding.DecomposeBlockAffine(encoding.ComposedBlocks{
		constr3.Last,
		encoding.InverseBlock{lastEncoding},
	}).BlockLinear.Forwards.Invert()

	fmt.Println(rightParasite.OctaveString())
	fmt.Println(leftParasite.OctaveString())

	fmt.Println(leftParasite.Compose(MC).Compose(rightParasite).Equals(constr3.Affine.BlockLinear.Forwards))

	// fmt.Println(encoding.DecomposeBlockAffine(encoding.ComposedBlocks{
	// 	constr3.Last,
	// 	encoding.InverseBlock{lastEncoding},
	// }))
	// aff2 := encoding.DecomposeBlockAffine(cipher3)

	// fmt.Println(aff2.BlockLinear.Forwards.String())
	// fmt.Println(aff.BlockLinear.Forwards.Compose(aff2.BlockLinear.Backwards).OctaveString())

}

// func TestDecomposeSAS(t *testing.T) {
// 	constr1 := sas.GenerateKeys(rand.Reader)
// 	constr2 := DecomposeSAS(constr1)
//
// 	// Check that both constructions give the same output on a random challenge.
// 	challenge := make([]byte, 16)
// 	rand.Read(challenge)
//
// 	cand1, cand2 := make([]byte, 16), make([]byte, 16)
// 	constr1.Encrypt(cand1, challenge)
// 	constr2.Encrypt(cand2, challenge)
//
// 	if bytes.Compare(cand1, cand2) != 0 {
// 		t.Fatalf("Construction #1 and construction #2 didn't agree at a random challenge!")
// 	}
// }

// func TestRecoverLastSBoxes(t *testing.T) {
// 	constr := sas.GenerateKeys(rand.Reader)
// 	cipher := Encoding{constr}
//
// 	last := RecoverLastSBoxes(cipher)
//
// 	aff := encoding.ComposedBlocks{
// 		encoding.InverseBlock{constr.First},
// 		cipher,
// 		encoding.InverseBlock{last},
// 	}
//
// 	if !testAffine(aff) {
// 		t.Fatalf("Affine test on encryption without tailing s-boxes failed.")
// 	}
// }

// func TestRecoverFirstSBoxes(t *testing.T) {
// 	constr := sas.GenerateKeys(rand.Reader)
// 	cipher := encoding.ComposedBlocks{
// 		Encoding{constr},
// 		encoding.InverseBlock{constr.Last},
// 	}
//
// 	first := RecoverFirstSBoxes(cipher)
//
// 	aff := encoding.ComposedBlocks{
// 		encoding.InverseBlock{first},
// 		cipher,
// 	}
//
// 	if !testAffine(aff) {
// 		t.Fatalf("Affine test on encryption without s-boxes on either side failed.")
// 	}
// }

func TestFirstSBoxConstraints(t *testing.T) {
	pos := 0
	constr := sas.GenerateKeys(rand.Reader)
	cipher := encoding.ComposedBlocks{
		Encoding{constr},
		encoding.InverseBlock{constr.Last},
	}

	a, b := cipher.Encode(XatY(0x00, pos)), cipher.Encode(XatY(0x01, pos))
	target := [16]byte{}
	encoding.XOR(target[:], a[:], b[:])

	m := FirstSBoxConstraints(cipher, pos, target)

	sbox := constr.First[pos].(encoding.SBox)
	c := sbox.Encode(0x00) ^ sbox.Encode(0x01)

	sboxRow := gfmatrix.NewRow(256)
	for i := 0; i < 256; i++ {
		sboxRow[i] = number.ByteFieldElem(sbox.EncKey[i])
	}

	// Verify that the dot product of each balance row with the S-Box equals the correct constant.
	for _, row := range m {
		cand := byte(row.DotProduct(sboxRow))
		if cand != c {
			t.Fatalf("FirstSBoxConstraints gave an incorrect relation! %v != %v", cand, c)
		}
	}
}
