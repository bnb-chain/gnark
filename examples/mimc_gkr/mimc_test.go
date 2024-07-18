// Copyright 2020 ConsenSys AG
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

package mimc

import (
	"github.com/consensys/gnark-crypto/ecc"
	"github.com/consensys/gnark/backend/groth16"
	"github.com/consensys/gnark/frontend"
	"github.com/consensys/gnark/frontend/cs/r1cs"
	"github.com/consensys/gnark/test"
	"testing"
)

func TestPreimage(t *testing.T) {
	assert := test.NewAssert(t)

	// Creates the assignments values
	var bN = 4
	var mimcCircuit = Circuit{
		PreImage: "16130099170765464552823636852555369511329944820189892919423002775646948828469",
		Hash:     "13773339841907060410779975660651653092173439740197484094397177791676767249280",
	}
	mimcCircuit.GKRs.AllocateGKRCircuit(bN)

	// circuit
	var circuit Circuit
	circuit.GKRs.AllocateGKRCircuit(bN)
	ccs, err := frontend.Compile(ecc.BN254.ScalarField(), r1cs.NewBuilder, &circuit, frontend.IgnoreUnconstrainedInputs(), frontend.WithGKRBN(bN))
	assert.NoError(err)
	ccs.Lazify()

	pk, vk, err := groth16.Setup(ccs)
	assert.NoError(err)

	// groth16: Prove & Verify
	witness, err := frontend.NewWitness(&mimcCircuit, ecc.BN254.ScalarField())
	assert.NoError(err)

	proof, err := groth16.Prove(ccs, pk, witness)
	assert.NoError(err)

	publicWitness, err := witness.Public()
	assert.NoError(err)

	err = groth16.Verify(proof, vk, publicWitness)
	assert.NoError(err)

}

func TestPreimagePoseidon(t *testing.T) {
	assert := test.NewAssert(t)

	// Creates the assignments values
	var bN = 4
	var mimcCircuit = CircuitByPoseidon{
		PreImage: "16130099170765464552823636852555369511329944820189892919423002775646948828469",
		Hash:     "13773339841907060410779975660651653092173439740197484094397177791676767249280",
	}

	// circuit
	var circuit CircuitByPoseidon
	ccs, err := frontend.Compile(ecc.BN254.ScalarField(), r1cs.NewBuilder, &circuit, frontend.IgnoreUnconstrainedInputs(), frontend.WithGKRBN(bN))
	assert.NoError(err)

	pk, vk, err := groth16.Setup(ccs)
	assert.NoError(err)

	// groth16: Prove & Verify
	witness, err := frontend.NewWitness(&mimcCircuit, ecc.BN254.ScalarField())
	assert.NoError(err)

	proof, err := groth16.Prove(ccs, pk, witness)
	assert.NoError(err)

	publicWitness, err := witness.Public()
	assert.NoError(err)

	err = groth16.Verify(proof, vk, publicWitness)
	assert.NoError(err)

}