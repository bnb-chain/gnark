package gkr_mimc

import (
	"github.com/consensys/gnark-crypto/ecc/bn254/fr"
	"github.com/consensys/gnark/frontend"
	gkrNative "github.com/consensys/gnark/std/gkr/gkr"
	"github.com/consensys/gnark/std/gkr/snark/gkr"
	"github.com/consensys/gnark/std/gkr/snark/polynomial"
)

type GKRMimcTestCircuit struct {
	Circuit                 gkr.Circuit
	Proof                   gkr.Proof
	QInitial, QInitialprime []frontend.Variable
	VInput, VOutput         polynomial.MultilinearByValues
}

func AllocateGKRMimcTestCircuit(bN int) GKRMimcTestCircuit {
	circuit := gkr.CreateMimcCircuit()
	return GKRMimcTestCircuit{
		Circuit:       circuit,
		Proof:         gkr.AllocateProof(bN, circuit),
		QInitial:      []frontend.Variable{},
		QInitialprime: make([]frontend.Variable, bN),
		VInput:        polynomial.AllocateMultilinear(bN + 1),
		VOutput:       polynomial.AllocateMultilinear(bN),
	}
}

func (c *GKRMimcTestCircuit) Assign(
	proof gkrNative.Proof,
	inputs [][]fr.Element,
	outputs [][]fr.Element,
	qInitialprime []fr.Element,
) {
	c.Proof.Assign(proof)
	for i := range qInitialprime {
		c.QInitialprime[i] = qInitialprime[i]
	}
	c.VInput.AssignFromChunkedBKT(inputs)
	c.VOutput.AssignFromChunkedBKT(outputs)
}

func (c *GKRMimcTestCircuit) Define(cs frontend.API) error {
	c.Proof.AssertValid(cs, c.Circuit, c.QInitial, c.QInitialprime, c.VInput, c.VOutput)
	return nil
}
