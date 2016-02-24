package spn

import (
  "crypto/rand"

  "github.com/OpenWhiteBox/primitives/encoding"
  "github.com/OpenWhiteBox/primitives/matrix"
)

// findIntersections returns the incremental matrix containing only the rowspace that a set of given incremental
// matrices have in common.
func findIntersections(ims []matrix.IncrementalMatrix) matrix.IncrementalMatrix {
	out := findIntersection(ims[0], ims[1])

	for i := 2; i < len(ims); i++ {
		out = findIntersection(out, ims[i])
	}

	return out
}

// findIntersection returns the incremental matrix containing only the rowspace that the two given incremental matrices
// have in common.
func findIntersection(aT, bT matrix.IncrementalMatrix) matrix.IncrementalMatrix {
	a, b := aT.Dup(), bT.Dup()
  aM, bM := a.Matrix()[0:a.Len()], b.Matrix()[0:b.Len()]
  _, size := bM.Size()

  // Concatenate the two matrices and find the nullspace of the concatenated matrix.
	m := append(aM, bM...)
  basis := m.Transpose().NullSpace()

  // The nullspace contains all the linear combinations that cause the two matrices to equal. Extract a basis for these
  // vectors for just one matrix.
	out := matrix.NewIncrementalMatrix(size)

	for _, row := range basis {
		v := matrix.NewRow(size)

		for i := 0; i < a.Len(); i++ {
			if row.GetBit(i) == 1 {
				v = v.Add(aM[i])
			}
		}

		out.Add(v)
	}

	return out
}

// trivialSubspaces generates subspaces by fixing one input and letting the rest vary.
func trivialSubspaces(cipher encoding.Block) (subspaces []matrix.IncrementalMatrix) {
  for pos := 0; pos < 16; pos++ {
    subspace := matrix.NewIncrementalMatrix(128)

    for i := 0; i < 129 && subspace.Len() < 120; i++ {
      x, y := [16]byte{}, [16]byte{}
      rand.Read(x[:])
      rand.Read(y[:])
      x[pos], y[pos] = 0x00, 0x00

      x, y = cipher.Encode(x), cipher.Encode(y)

      subspace.Add(matrix.Row(x[:]).Add(matrix.Row(y[:])))
    }

    if subspace.Len() != 120 {
      panic("Found incorrectly sized subspace!")
    }

    subspaces = append(subspaces, subspace)
  }

  return
}

// lowRankDetection generates subspaces by choosing random pairs of inputs and checking if the linear span of their
// output is the right size.
func lowRankDetection(cipher encoding.Block) (subspaces []matrix.IncrementalMatrix) {
	for attempt := 0; attempt < 2000 && len(subspaces) < 16; attempt++ {
    // Generate a random subspace.
    x, y := [16]byte{}, [16]byte{}
    rand.Read(x[:])
    rand.Read(y[:])

    subspace := matrix.NewIncrementalMatrix(128)

    for i := 0; i < 129 && subspace.Len() <= 120; i++ {
      x[attempt%16], y[attempt%16] = byte(i), byte(i)
      X, Y := cipher.Encode(x), cipher.Encode(y)

      subspace.Add(matrix.Row(X[:]).Add(matrix.Row(Y[:])))
    }

    // Discard it if it's the wrong size.
    if subspace.Len() != 120 {
      continue
    }

    // Discard it if it overlaps too much with what we already have.
		dup := false
		for _, cand := range subspaces {
			intersection := findIntersection(subspace, cand)

			if intersection.Len() != 112 {
				dup = true
				break
			}
		}

		if dup {
      continue
    }

    // Not discarded, so keep it.
		subspaces = append(subspaces, subspace)
	}

	if len(subspaces) < 16 {
		panic("Failed to recover enough subspaces.")
	}

	return
}

// RecoverAffine finds inputs that cause the internal state of the cipher to collide with something like Low Rank
// Detection and uses them to remove the trailing affine layer.
func RecoverAffine(cipher encoding.Block, generator func(encoding.Block) []matrix.IncrementalMatrix) (last encoding.BlockAffine, rest encoding.Block) {
  subspaces := generator(cipher)

  // Recover span of each column by intersecting 15 others
  m := matrix.Matrix{}

  for excluded := 0; excluded < 16; excluded++ {
    remaining := []matrix.IncrementalMatrix{}

    for i := 0; i < 16; i++ {
      if i != excluded {
        remaining = append(remaining, subspaces[i])
      }
    }

    intersection := findIntersections(remaining)

    for bit := uint(0); bit < 8; bit++ {
      m = append(m, intersection.Row(1<<bit))
    }
  }

  last = encoding.NewBlockAffine(m.Transpose(), [16]byte{})
  return last, encoding.ComposedBlocks{cipher, encoding.InverseBlock{last}}
}
