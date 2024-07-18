package regressiontests

import (
	"math/big"
	"testing"

	"fmt"
	"github.com/consensys/gnark-crypto/ecc"
	"github.com/consensys/gnark/backend"
	"github.com/consensys/gnark/backend/hint"
	"github.com/consensys/gnark/frontend"
	"github.com/consensys/gnark/test"
)

type CmpCircuit struct {
	Left      frontend.Variable
	Right     frontend.Variable
	ExpCmpRes frontend.Variable
}

func (c *CmpCircuit) Define(api frontend.API) error {
	r := api.Cmp(c.Left, c.Right)
	api.AssertIsEqual(r, c.ExpCmpRes)
	return nil
}

type AssertIsLessOrEqCircuit struct {
	Smaller, Bigger frontend.Variable
}

func (c *AssertIsLessOrEqCircuit) Define(api frontend.API) error {
	api.AssertIsLessOrEqual(c.Smaller, c.Bigger)
	return nil
}

func getNBitsHint() (hint.ID, error) {

	for _, v := range hint.GetRegistered() {
		if hint.Name(v) == "github.com/consensys/gnark/std/math/bits.NBits" {
			return hint.UUID(v), nil
		}
	}
	return 0, fmt.Errorf("nBits hint not found")
}

func TestIssue836Cmp(t *testing.T) {
	assert := test.NewAssert(t)
	assignmentNoHintGood := CmpCircuit{
		Left:      10,
		Right:     5,
		ExpCmpRes: 1,
	}
	assignmentNoHintBad := CmpCircuit{
		Left:      5,
		Right:     10,
		ExpCmpRes: 1,
	}
	assignmentHintBad := CmpCircuit{
		Left:      10,
		Right:     5,
		ExpCmpRes: -1,
	}
	toReplaceHint, err := getNBitsHint()
	if err != nil {
		t.Fatalf("couldn't find hint to replace: %v", err)
	}

	assert.SolvingSucceeded(&CmpCircuit{}, &assignmentNoHintGood, test.WithCurves(ecc.BN254), test.WithBackends(backend.GROTH16))
	assert.SolvingFailed(&CmpCircuit{}, &assignmentNoHintBad, test.WithCurves(ecc.BN254), test.WithBackends(backend.GROTH16))
	assert.SolvingFailed(&CmpCircuit{}, &assignmentHintBad, test.WithCurves(ecc.BN254), test.WithBackends(backend.GROTH16), test.WithProverOpts(func(pc *backend.ProverConfig) error {
		pc.HintFunctions[toReplaceHint] = maliciousNbitsHint
		return nil
	}))

}

func TestIssue836AssertIsLess(t *testing.T) {
	assert := test.NewAssert(t)
	assignmentNoHintGood := AssertIsLessOrEqCircuit{
		Smaller: 5,
		Bigger:  10,
	}
	assignmentNoHintBad := AssertIsLessOrEqCircuit{
		Smaller: 11,
		Bigger:  10,
	}
	// fr, _ := new(big.Int).SetString("21888242871839275222246405745257275088548364400416034343698204186575808495617", 10)
	assignmentHintBad := AssertIsLessOrEqCircuit{
		Smaller: 10,
		Bigger:  0,
	}
	toReplaceHint, err := getNBitsHint()
	if err != nil {
		t.Fatalf("couldn't find hint to replace: %v", err)
	} else {
		fmt.Println("find hint id ", toReplaceHint)
	}

	assert.SolvingSucceeded(&AssertIsLessOrEqCircuit{}, &assignmentNoHintGood, test.WithCurves(ecc.BN254), test.WithBackends(backend.GROTH16))
	assert.SolvingFailed(&AssertIsLessOrEqCircuit{}, &assignmentNoHintBad, test.WithCurves(ecc.BN254), test.WithBackends(backend.GROTH16))
	assert.SolvingFailed(&AssertIsLessOrEqCircuit{}, &assignmentHintBad, test.WithCurves(ecc.BN254), test.WithBackends(backend.GROTH16), test.WithProverOpts(func(pc *backend.ProverConfig) error {
		pc.HintFunctions[toReplaceHint] = maliciousNbitsHint
		return nil
	}))
}

func maliciousNbitsHint(mod *big.Int, inputs []*big.Int, results []*big.Int) error {
	n := inputs[0]
	// This is a malicious hint. If n is less equal than 5, then add the
	// modulus. This creates a non-unique binary decomposition of the value.
	if n.Cmp(big.NewInt(5)) <= 0 {
		n = n.Add(n, mod)
	}
	for i := 0; i < len(results); i++ {
		results[i].SetUint64(uint64(n.Bit(i)))
	}
	return nil
}
