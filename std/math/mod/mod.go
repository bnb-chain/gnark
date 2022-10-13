package mod

import (
	"github.com/consensys/gnark-crypto/ecc"
	"github.com/consensys/gnark/backend/hint"
	"math/big"
)

func init() {
	// register hints
	hint.Register(BigMulModP)
	hint.Register(BigAddModP)
	hint.Register(MultiBigMulAndAddGetMod)
}

func BigMulModP(_ ecc.ID, inputs []*big.Int, results []*big.Int) error {
	mul1 := inputs[0]
	mul2 := inputs[1]
	mul3 := mul1.Mul(mul1, mul2)
	mul3Mod := new(big.Int).Set(mul3)
	mul3Div := new(big.Int).Set(mul3)
	p := inputs[2]
	divResult := mul3Div.Div(mul3Div, p)
	results[0].SetBytes(divResult.Bytes())
	results[1].SetBytes(mul3Mod.Mod(mul3Mod, p).Bytes())
	return nil
}

func BigAddModP(_ ecc.ID, inputs []*big.Int, results []*big.Int) error {
	mul1 := inputs[0]
	mul2 := inputs[1]
	mul3 := mul1.Add(mul1, mul2)
	mul3Mod := new(big.Int).Set(mul3)
	p := inputs[2]
	results[0].SetBytes(mul3.Div(mul3, p).Bytes())
	results[1].SetBytes(mul3Mod.Mod(mul3Mod, p).Bytes())
	return nil
}

func MultiBigMulAndAddGetMod(_ ecc.ID, inputs []*big.Int, results []*big.Int) error {
	sum := new(big.Int).SetUint64(0)
	for i := 1; i < len(inputs); i += 2 {
		mul := new(big.Int)
		mul.Mul(inputs[i], inputs[i+1])
		sum.Add(sum, mul)
	}
	sum3 := new(big.Int).Set(sum)
	summod := new(big.Int).Set(sum)
	results[0].SetBytes(sum3.Div(sum3, inputs[0]).Bytes())
	results[1].SetBytes(summod.Mod(summod, inputs[0]).Bytes())
	return nil
}
