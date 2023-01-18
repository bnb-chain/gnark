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
	"github.com/consensys/gnark/backend/hint"
	"github.com/consensys/gnark/examples/gkr_mimc"
	"github.com/consensys/gnark/frontend"
	"github.com/consensys/gnark/std/hash/mimc"
)

// Circuit defines a pre-image knowledge proof
// mimc(secret preImage) = public hash
type Circuit struct {
	// struct tag on a variable is optional
	// default uses variable name and secret visibility.
	PreImage frontend.Variable
	Hash     frontend.Variable `gnark:",public"`
	GKR      gkr_mimc.GKRMimcTestCircuit
}

// Define declares the circuit's constraints
// Hash = mimc(PreImage)
func (circuit *Circuit) Define(api frontend.API) error {
	// hash function
	for i := 0; i < 1; i++ {
		//circuit.Hash2BySamePreImage(api)
		circuit.Hash2BySamePreImageHint(api)
	}
	c := circuit.GKR
	c.Proof.AssertValid(api, c.Circuit, c.QInitial, c.QInitialprime, c.VInput, c.VOutput)
	return nil
}

// Hash2BySamePreImage 547 constriants for hashing 2 elements
func (circuit *Circuit) Hash2BySamePreImage(api frontend.API) {
	mimc, _ := mimc.NewMiMC(api)

	// specify constraints
	// mimc(preImage) == hash
	mimc.Write(circuit.PreImage, circuit.PreImage)
	api.AssertIsEqual(circuit.Hash, mimc.Sum())
}

// Hash2BySamePreImageHint 1 constriants for hashing 2 elements
func (circuit *Circuit) Hash2BySamePreImageHint(api frontend.API) {
	results, err := api.Compiler().NewHint(hint.MIMC2Elements, 1, circuit.PreImage, circuit.PreImage)
	if err != nil {
		panic(err)
	}
	api.AssertIsEqual(circuit.Hash, results[0])
}
