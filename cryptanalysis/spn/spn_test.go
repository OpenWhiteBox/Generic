package spn

import (
	"fmt"
	"testing"

	"crypto/rand"

	"github.com/OpenWhiteBox/primitives/encoding"

	"github.com/OpenWhiteBox/Generic/constructions/spn"
)

func ExampleDecomposeSPN() {
	constr1 := spn.NewSPN(rand.Reader, spn.SAS)
	constr2 := DecomposeSPN(constr1, spn.SAS)

	ok := encoding.ProbablyEquivalentBlocks(
		Encoding{constr1},
		Encoding{constr2},
	)

	fmt.Println(ok)
	// Output:
	// true
}

func TestDecomposeAS(t *testing.T) {
	constr1 := spn.NewSPN(rand.Reader, spn.AS)
	constr2 := DecomposeSPN(constr1, spn.AS)

	ok := encoding.ProbablyEquivalentBlocks(
		Encoding{constr1},
		Encoding{constr2},
	)

	if !ok {
		t.Fatal("Incorrectly decomposed AS structure!")
	}
}

func TestDecomposeSA(t *testing.T) {
	constr1 := spn.NewSPN(rand.Reader, spn.SA)
	constr2 := DecomposeSPN(constr1, spn.SA)

	ok := encoding.ProbablyEquivalentBlocks(
		Encoding{constr1},
		Encoding{constr2},
	)

	if !ok {
		t.Fatal("Incorrectly decomposed SA structure!")
	}
}

func TestDecomposeASA(t *testing.T) {
	constr1 := spn.NewSPN(rand.Reader, spn.ASA)
	constr2 := DecomposeSPN(constr1, spn.ASA)

	ok := encoding.ProbablyEquivalentBlocks(
		Encoding{constr1},
		Encoding{constr2},
	)

	if !ok {
		t.Fatal("Incorrectly decomposed ASA structure!")
	}
}

func TestDecomposeSAS(t *testing.T) {
	constr1 := spn.NewSPN(rand.Reader, spn.SAS)
	constr2 := DecomposeSPN(constr1, spn.SAS)

	ok := encoding.ProbablyEquivalentBlocks(
		Encoding{constr1},
		Encoding{constr2},
	)

	if !ok {
		t.Fatal("Incorrectly decomposed SAS structure!")
	}
}

func TestDecomposeASAS(t *testing.T) {
	constr1 := spn.NewSPN(rand.Reader, spn.ASAS)
	constr2 := DecomposeSPN(constr1, spn.ASAS)

	ok := encoding.ProbablyEquivalentBlocks(
		Encoding{constr1},
		Encoding{constr2},
	)

	if !ok {
		t.Fatal("Incorrectly decomposed ASAS structure!")
	}
}

func TestDecomposeSASA(t *testing.T) {
	constr1 := spn.NewSPN(rand.Reader, spn.SASA)
	constr2 := DecomposeSPN(constr1, spn.SASA)

	ok := encoding.ProbablyEquivalentBlocks(
		Encoding{constr1},
		Encoding{constr2},
	)

	if !ok {
		t.Fatal("Incorrectly decomposed SASA structure!")
	}
}

func TestDecomposeASASA(t *testing.T) {
	t.Skip()
}

func TestDecomposeSASAS(t *testing.T) {
	constr1 := spn.NewSPN(rand.Reader, spn.SASAS)
	constr2 := DecomposeSPN(constr1, spn.SASAS)

	ok := encoding.ProbablyEquivalentBlocks(
		Encoding{constr1},
		Encoding{constr2},
	)

	if !ok {
		t.Fatal("Incorrectly decomposed SASAS structure!")
	}
}
