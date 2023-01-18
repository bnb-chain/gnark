package hint

import (
	"github.com/consensys/gnark-crypto/ecc/bn254/fr"
	"github.com/consensys/gnark/std/gkr/hash"
	"math/big"

	"github.com/consensys/gnark-crypto/ecc"
)

func init() {
	Register(IsZero)
	Register(Self)
	Register(MIMC2Elements)
}

// IsZero computes the value 1 - a^(modulus-1) for the single input a. This
// corresponds to checking if a == 0 (for which the function returns 1) or a
// != 0 (for which the function returns 0).
func IsZero(curveID ecc.ID, inputs []*big.Int, results []*big.Int) error {
	result := results[0]

	// get fr modulus
	q := curveID.Info().Fr.Modulus()

	// save input
	result.Set(inputs[0])

	// reuse input to compute q - 1
	qMinusOne := inputs[0].SetUint64(1)
	qMinusOne.Sub(q, qMinusOne)

	// result =  1 - input**(q-1)
	result.Exp(result, qMinusOne, q)
	inputs[0].SetUint64(1)
	result.Sub(inputs[0], result).Mod(result, q)

	return nil
}

func Self(curveID ecc.ID, inputs []*big.Int, results []*big.Int) error {
	results[0].Set(inputs[0])
	return nil
}

func MIMC2Elements(curveID ecc.ID, inputs []*big.Int, results []*big.Int) error {
	newState := new(fr.Element).SetBigInt(inputs[1])
	block := new(fr.Element).SetBigInt(inputs[0])
	oldState := new(fr.Element).SetBigInt(inputs[1])
	block.Sub(block, oldState)
	hash.MimcPermutationInPlace(newState, *block)
	bytes := newState.Bytes()
	results[0].SetBytes(bytes[:])
	return nil
}
