package gkr

import (
	"fmt"
	"github.com/consensys/gnark-crypto/ecc/bn254/fr"
	"github.com/consensys/gnark/std/gkr/circuit"
	"github.com/consensys/gnark/std/gkr/common"
	"github.com/stretchr/testify/assert"
	"testing"
)

func TestGKR(t *testing.T) {
	var one fr.Element
	one.SetOne()

	c := circuit.NewCircuit(
		[][]circuit.Wire{
			// Layer 0
			{
				circuit.Wire{L: 0, R: 1, O: 0, Gate: circuit.AddGate{}},
				circuit.Wire{L: 0, R: 1, O: 1, Gate: circuit.MulGate{}},
			},
			// Layer 1
			{
				circuit.Wire{L: 0, R: 1, O: 0, Gate: circuit.AddGate{}},
				circuit.Wire{L: 0, R: 1, O: 1, Gate: circuit.MulGate{}},
			},
		},
	)

	inputs := [][]fr.Element{
		{common.Uint64ToFr(1), common.Uint64ToFr(2)},
		{common.Uint64ToFr(3), common.Uint64ToFr(4)},
	}

	a := c.Assign(inputs, 2)

	expectedValues := [][][]fr.Element{
		{
			[]fr.Element{common.Uint64ToFr(1), common.Uint64ToFr(2)},
			[]fr.Element{common.Uint64ToFr(3), common.Uint64ToFr(4)},
		},
		{
			[]fr.Element{common.Uint64ToFr(3), common.Uint64ToFr(2)},
			[]fr.Element{common.Uint64ToFr(7), common.Uint64ToFr(12)},
		},
		{
			[]fr.Element{common.Uint64ToFr(5), common.Uint64ToFr(6)},
			[]fr.Element{common.Uint64ToFr(19), common.Uint64ToFr(84)},
		},
	}

	assert.Equal(
		t,
		expectedValues,
		a.Values,
		"Assignment invalid.",
	)

	outputs := a.Values[2]

	challenges := make([]string, 0)
	for i := len(c.Layers) - 1; i >= 0; i-- {
		// 2 * bG + bN, bN here is 1
		for j := 0; j < 2*c.Layers[i].BGOutputs+1; j++ {
			challenges = append(challenges, fmt.Sprintf("layers.%d.hpolys.%d", i, j))
		}
		challenges = append(challenges, fmt.Sprintf("layers.%d.next", i-1))
	}
	// will use commit during snarks
	initialHash := &fr.Element{0}
	p := NewProver(c, a, initialHash)
	proof := p.Prove(1, challenges...)

	v := NewVerifier(1, c)
	validity := v.Verify(proof, inputs, outputs, initialHash, challenges...)

	assert.Equal(
		t,
		validity,
		true,
		"Proof invalid.",
	)
}
