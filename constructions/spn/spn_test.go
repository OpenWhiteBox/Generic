package spn

import (
	"testing"

	"bytes"
	"crypto/rand"
)

func Example_encrypt() {
	constr := NewSPN(rand.Reader, SAS) // crypto/rand.Reader

	dst, src := make([]byte, 16), make([]byte, 16)
	constr.Encrypt(dst, src)
}

func TestEncrypt(t *testing.T) {
	constr := NewSPN(rand.Reader, SAS)

	in := make([]byte, 16)
	out := make([]byte, 16)
	out2 := make([]byte, 16)

	constr.Encrypt(out, in)
	constr.Decrypt(out2, out)

	if !bytes.Equal(in, out2) {
		t.Fatalf("Correctness property is not satisfied.")
	}
}

func TestPersistence(t *testing.T) {
	constr := NewSPN(rand.Reader, SAS)

	serialized := constr.Serialize()
	constr2 := Parse(serialized, SAS)

	in := make([]byte, 16)
	rand.Read(in)

	out := make([]byte, 16)
	out2 := make([]byte, 16)

	constr.Encrypt(out, in)
	constr2.Encrypt(out2, in)

	if !bytes.Equal(out, out2) {
		t.Fatalf("Parse/Serialize are wrong.")
	}
}
