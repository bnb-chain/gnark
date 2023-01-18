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
	"fmt"
	"github.com/consensys/gnark-crypto/ecc"
	"github.com/consensys/gnark/backend/groth16"
	"github.com/consensys/gnark/examples/gkr_mimc"
	"github.com/consensys/gnark/frontend"
	"github.com/consensys/gnark/frontend/cs/r1cs"
	"github.com/consensys/gnark/std/gkr/common"
	"github.com/consensys/gnark/std/gkr/examples"
	"github.com/consensys/gnark/std/gkr/gkr"
	"math/big"
	"testing"

	"github.com/consensys/gnark/test"
)

func TestPreimage(t *testing.T) {
	assert := test.NewAssert(t)

	var mimcCircuit = Circuit{
		PreImage: "16130099170765464552823636852555369511329944820189892919423002775646948828469",
		Hash:     "20568119741485842979359920820457607712024599461690104759159310350948929750336",
	}

	var bN = 1

	preImage, _ := new(big.Int).SetString("15130099170765464552823636852555369511329944820189892919423002775646948828469", 10)
	// Creates the assignments values
	nativeCircuit := examples.CreateMimcCircuit()
	inputs := common.PickInputs([]*big.Int{preImage, preImage, preImage, preImage}, 2*(1<<bN))
	assignment := nativeCircuit.Assign(inputs, 1)
	outputs := assignment.Values[91]

	prover := gkr.NewProver(nativeCircuit, assignment)
	proofg := prover.Prove(1)
	qInitialprime, _ := gkr.GetInitialQPrimeAndQ(bN, 0)

	mimcCircuit.GKR = gkr_mimc.AllocateGKRMimcTestCircuit(bN)
	mimcCircuit.GKR.Assign(proofg, inputs, outputs, qInitialprime)

	var circuit Circuit
	circuit.GKR = gkr_mimc.AllocateGKRMimcTestCircuit(bN)
	mimcCircuit.GKR.Assign(proofg, inputs, outputs, qInitialprime)
	ccs, err := frontend.Compile(ecc.BN254, r1cs.NewBuilder, &circuit, frontend.IgnoreUnconstrainedInputs())

	pk, vk, err := groth16.Setup(ccs)

	witness, err := frontend.NewWitness(&mimcCircuit, ecc.BN254)
	assert.NoError(err)
	publicWitness, _ := witness.Public()

	// groth16: Prove & Verify
	proof, err := groth16.Prove(ccs, pk, witness)
	fmt.Println(err)
	err = groth16.Verify(proof, vk, publicWitness)
	assert.NoError(err)

}
