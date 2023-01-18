package gkr_mimc

import (
	"fmt"
	"github.com/consensys/gnark-crypto/ecc"
	"github.com/consensys/gnark/backend"
	"github.com/consensys/gnark/std/gkr/common"
	"github.com/consensys/gnark/std/gkr/examples"
	"github.com/consensys/gnark/std/gkr/gkr"
	"github.com/consensys/gnark/test"
	"testing"
)

func TestGKRPreimage(t *testing.T) {
	bN := 4
	assert := test.NewAssert(t)

	mimcCircuit := AllocateGKRMimcTestCircuit(bN)
	// Attempt to compile the circuit

	// Generate the witness values by running the prover
	var witness GKRMimcTestCircuit

	// Creates the assignments values
	nativeCircuit := examples.CreateMimcCircuit()
	inputs := common.RandomFrDoubleSlice(1, 2*(1<<bN))
	assignment := nativeCircuit.Assign(inputs, 1)
	outputs := assignment.Values[91]
	fmt.Print(len(outputs[0]))

	prover := gkr.NewProver(nativeCircuit, assignment)
	proof := prover.Prove(1)
	qInitialprime, _ := gkr.GetInitialQPrimeAndQ(bN, 0)

	// Assigns the values
	witness = AllocateGKRMimcTestCircuit(bN)
	witness.Assign(proof, inputs, outputs, qInitialprime)

	assert.SolvingSucceeded(&mimcCircuit, &witness, test.WithBackends(backend.GROTH16), test.WithCurves(ecc.BN254))
	// Takes 200sec on my laptop
	// assert.ProverSucceeded( &witness)

	//assert.ProverSucceeded(&mimcCircuit, &Circuit{
	//	PreImage: "16130099170765464552823636852555369511329944820189892919423002775646948828469",
	//	Hash:     "8674594860895598770446879254410848023850744751986836044725552747672873438975",
	//}, test.WithCurves(ecc.BN254))

}
