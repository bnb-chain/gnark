package compiled

import (
	"github.com/consensys/gnark-crypto/ecc"
	"github.com/consensys/gnark/frontend"
	"github.com/consensys/gnark/frontend/schema"
	"github.com/consensys/gnark/std/hash/poseidon/constants"
	"math/big"
	"os"
	"sort"
	"strconv"
)

type LazyPoseidonInputs struct {
	S   []LinearExpression
	V   LinearExpression
	Loc int
}

func FetchLazyConstraint(S []LinearExpression, staticR1c []R1C, j int, Coefs CoeffTable) R1C {
	// s0 + v, s0 + v, s1 0
	// s1, s1, s2 1
	// s0 + v, s2, s3 2

	for i := range S {
		if j == i*3 {
			zero := LinearExpression{Pack(0, CoeffIdZero, schema.Public)}
			addRes := S[i]
			one := LinearExpression{Pack(0, CoeffIdOne, schema.Public)}
			cID := Coefs.GetCoeffID(constants.RC[len(S)-3][i])

			if cID == -1 {
				os.Exit(-1)
			}
			one[0].SetCoeffID(cID)
			one[0].SetCoeffID(cID)
			vars := make([]LinearExpression, 0, 1)
			vars = append(vars, one)
			for _, v := range vars {
				if v.Equal(zero) {
					continue
				}
				addRes = append(addRes, v...)
			}
			if !sort.IsSorted(addRes) {
				sort.Sort(addRes)
			}
			addRes = reduce(addRes, Coefs)
			resL := addRes.Clone()
			resR := addRes.Clone()
			resO := staticR1c[i*3].O.Clone()
			return R1C{
				L: resL,
				R: resR,
				O: resO,
			}
		}

		if j == i*3+2 {
			zero := LinearExpression{Pack(0, CoeffIdZero, schema.Public)}
			addRes := S[i]
			one := LinearExpression{Pack(0, CoeffIdOne, schema.Public)}
			cID := Coefs.GetCoeffID(constants.RC[len(S)-3][i])

			if cID == -1 {
				os.Exit(-1)
			}
			one[0].SetCoeffID(cID)
			one[0].SetCoeffID(cID)
			vars := make([]LinearExpression, 0, 1)
			vars = append(vars, one)
			for _, v := range vars {
				if v.Equal(zero) {
					continue
				}
				addRes = append(addRes, v...)
			}
			if !sort.IsSorted(addRes) {
				sort.Sort(addRes)
			}
			addRes = reduce(addRes, Coefs)
			resL := staticR1c[i*3+2].L.Clone()
			resR := addRes.Clone()
			resO := staticR1c[i*3+2].O.Clone()
			return R1C{
				L: resL,
				R: resR,
				O: resO,
			}

		}
	}

	resL := staticR1c[j].L.Clone()
	resR := staticR1c[j].R.Clone()
	resO := staticR1c[j].O.Clone()

	return R1C{
		L: resL,
		R: resR,
		O: resO,
	}
}

var ConstraintsMap []int

func init() {
	ConstraintsMap = []int{243, 264, 300, 324, 357, 384, 405, 420, 462, 468, 507}
}

func GetConstraintsNum(variables []frontend.Variable, api frontend.API) int {
	return ConstraintsMap[len(variables)-3]
}
func GetConstraintsNumLinear(variables []LinearExpression) int {
	return ConstraintsMap[len(variables)-3]
}

func StaticPoseidonR1CS(v frontend.Variable, Coefs CoeffTable, data ...LinearExpression) []R1C {
	t := len(data)
	if t < 3 || t > 13 {
		panic("Not supported input size")
	}
	state := make([]LinearExpression, t)
	copy(state[:], data)

	return StaticPermutation(v, state, Coefs)
}

func StaticPermutation(V frontend.Variable, state []LinearExpression, Coefs CoeffTable) []R1C {
	roundCounter := 0
	stateCopy := make([]LinearExpression, len(state))
	for i := 0; i < len(stateCopy); i++ {
		stateCopy[i] = state[i].Clone()
	}
	stateCopy, r1csFullRound1, wid := StaticFullRound(stateCopy, V, Coefs, &roundCounter, V.(LinearExpression)[0].WireID()-GetConstraintsNumLinear(state))
	stateCopy, r1csPartial1, wid := StaticPartial(stateCopy, V, Coefs, &roundCounter, wid)
	_, r1csFullRound2, _ := StaticFullRound(stateCopy, V, Coefs, &roundCounter, wid)

	resutls := make([]R1C, 0)
	resutls = append(resutls, r1csFullRound1...)
	resutls = append(resutls, r1csPartial1...)
	resutls = append(resutls, r1csFullRound2...)
	return resutls
}

func StaticFullRound(state []LinearExpression, V frontend.Variable, Coefs CoeffTable, roundCounter *int, initWid int) ([]LinearExpression, []R1C, int) {
	width := len(state)
	index := width - 3
	wid := initWid
	res := make([]R1C, 0)
	rf := constants.RF / 2
	for i := 0; i < rf; i++ {
		for j := 0; j < width; j++ {
			//state[j] = api.Add(state[j], constants.RC[index][*roundCounter])
			zero := LinearExpression{Pack(0, CoeffIdZero, schema.Public)}
			one := LinearExpression{Pack(0, CoeffIdOne, schema.Public)}
			cID := Coefs.GetCoeffID(constants.RC[index][*roundCounter])

			if cID == -1 {
				os.Exit(-1)
			}
			one[0].SetCoeffID(cID)
			vars := make([]LinearExpression, 0, 1)
			vars = append(vars, one)
			for _, v := range vars {
				if v.Equal(zero) {
					continue
				}
				state[j] = append(state[j], v...)
			}
			state[j] = reduce(state[j], Coefs)
			*roundCounter += 1

			// Apply single s-box
			//state[0] = sbox(api, state[0])
			// x = pow5(h.api, addRes)
			// // r = h.api.Mul(addRes, addRes)
			// // r = h.api.Mul(r, r)
			// // x = h.api.Mul(r, addRes)
			mod := ecc.BN254.Info().Fr.Modulus()
			addRes := state[j].Clone()
			r0, isContant := ConstantValue(state[j], Coefs)
			if isContant {
				r02 := new(big.Int).Mul(r0, r0)
				r04 := new(big.Int).Mul(r02, r02)
				r05 := new(big.Int).Mul(r04, r0)
				r05 = new(big.Int).Mod(r05, mod)
				ccId := Coefs.GetCoeffID(r05)
				state[j][0].SetCoeffID(ccId)
			} else {
				r := V.(LinearExpression).Clone()
				r[0].SetWireID(wid)
				res = append(res, R1C{
					L: addRes,
					R: addRes,
					O: r})
				r2 := r.Clone()
				r2[0].SetWireID(wid + 1)
				res = append(res, R1C{
					L: r,
					R: r,
					O: r2})
				r3 := r2.Clone()
				r3[0].SetWireID(wid + 2)
				res = append(res, R1C{
					L: r2,
					R: addRes,
					O: r3})

				wid += 3
				state[j] = r3.Clone() //TODO
			}
		}

		// Apply mix layer
		stateMix := StaticMixR1C(state, Coefs)
		state = stateMix
	}

	return state, res, wid
}

func StaticPartial(state []LinearExpression, V frontend.Variable, Coefs CoeffTable, roundCounter *int, wid int) ([]LinearExpression, []R1C, int) {
	width := len(state)
	index := width - 3
	res := make([]R1C, 0)

	for i := 0; i < constants.RP[index]; i++ {
		for j := 0; j < width; j++ {
			// Add round constants
			//state[j] = api.Add(state[j], constants.RC[index][*roundCounter])
			zero := LinearExpression{Pack(0, CoeffIdZero, schema.Public)}
			one := LinearExpression{Pack(0, CoeffIdOne, schema.Public)}
			cID := Coefs.GetCoeffID(constants.RC[index][*roundCounter])

			if cID == -1 {
				os.Exit(-1)
			}
			one[0].SetCoeffID(cID)
			vars := make([]LinearExpression, 0, 1)
			vars = append(vars, one)
			for _, v := range vars {
				if v.Equal(zero) {
					continue
				}
				state[j] = append(state[j], v...)
			}

			state[j] = reduce(state[j], Coefs)

			*roundCounter += 1
		}

		// Apply single s-box
		//state[0] = sbox(api, state[0])
		// x = pow5(h.api, addRes)
		// // r = h.api.Mul(addRes, addRes)
		// // r = h.api.Mul(r, r)
		// // x = h.api.Mul(r, addRes)
		mod := ecc.BN254.Info().Fr.Modulus()
		addRes := state[0].Clone()
		r0, isContant := ConstantValue(state[0], Coefs)
		if isContant {
			r02 := new(big.Int).Mul(r0, r0)
			r04 := new(big.Int).Mul(r02, r02)
			r05 := new(big.Int).Mul(r04, r0)
			r05 = new(big.Int).Mod(r05, mod)
			ccId := Coefs.GetCoeffID(r05)
			state[0][0].SetCoeffID(ccId)
		} else {
			r := V.(LinearExpression).Clone()
			r[0].SetWireID(wid)
			res = append(res, R1C{
				L: addRes,
				R: addRes,
				O: r})
			r2 := r.Clone()
			r2[0].SetWireID(wid + 1)
			res = append(res, R1C{
				L: r,
				R: r,
				O: r2})
			r3 := r2.Clone()
			r3[0].SetWireID(wid + 2)
			res = append(res, R1C{
				L: r2,
				R: addRes,
				O: r3})

			wid += 3
			state[0] = r3.Clone() //TODO
		}

		// Apply mix layer
		stateMix := StaticMixR1C(state, Coefs)
		state = stateMix
	}
	return state, res, wid
}

func StaticMixR1C(state []LinearExpression, Coefs CoeffTable) []LinearExpression {
	width := len(state)
	index := width - 3
	newState := make([]LinearExpression, width)
	mod := ecc.BN254.Info().Fr.Modulus()

	for i := 0; i < width; i++ {
		addRes := make(LinearExpression, 0)
		for j := 0; j < width; j++ {
			//mul := api.Mul(constants.MDS[index][i][j], state[j])
			cID := Coefs.GetCoeffID(constants.MDS[index][i][j])
			if cID == -1 {
				os.Exit(-1)
			}

			r0, isContant := ConstantValue(state[j], Coefs)
			var mul LinearExpression
			if isContant {
				r02 := r0.Mul(r0, constants.MDS[index][i][j])
				r02.Mod(r02, mod)
				ccId := Coefs.GetCoeffID(r02)
				mul = state[j].Clone()
				mul[0].SetCoeffID(ccId)
			} else {
				mul = mulConstant(state[j], Coefs.GetCoeffsById(cID), Coefs)
			}

			// acc = api.Add(acc, mul)
			zero := LinearExpression{Pack(0, CoeffIdZero, schema.Public)}
			vars := make([]LinearExpression, 0, 1)
			vars = append(vars, mul)
			for _, v := range vars {
				if v.Equal(zero) {
					continue
				}
				addRes = append(addRes, v...)
			}
			addRes = reduce(addRes, Coefs)
		}
		newState[i] = reduce(addRes, Coefs)
	}
	return newState
}

func mulConstant(v1 LinearExpression, lambda *big.Int, Coefs CoeffTable) LinearExpression {
	// multiplying a frontend.Variable by a constant -> we updated the coefficients in the linear expression
	// leading to that frontend.Variable
	res := v1.Clone()

	for i, t := range v1 {
		cID, vID, visibility := t.Unpack()
		var newCoeff big.Int
		switch cID {
		case CoeffIdMinusOne:
			newCoeff.Neg(lambda)
		case CoeffIdZero:
			newCoeff.SetUint64(0)
		case CoeffIdOne:
			newCoeff.Set(lambda)
		case CoeffIdTwo:
			newCoeff.Add(lambda, lambda)
		default:
			coeff := Coefs.GetCoeffsById(cID)
			newCoeff.Mul(coeff, lambda)
		}
		res[i] = Pack(vID, Coefs.CoeffID(&newCoeff), visibility)
	}
	return res
}

func reduce(state LinearExpression, Coefs CoeffTable) LinearExpression {
	if !sort.IsSorted(state) {
		sort.Sort(state)
	}
	// // TODO Reduce just check 0?
	mod := ecc.BN254.Info().Fr.Modulus()
	c := new(big.Int)
	for i := 1; i < len(state); i++ {
		pcID, pvID, pVis := state[i-1].Unpack()
		ccID, cvID, cVis := state[i].Unpack()
		if pVis == cVis && pvID == cvID {
			// we have redundancy
			c.Add(Coefs.GetCoeffsById(pcID), Coefs.GetCoeffsById(ccID))
			c.Mod(c, mod)
			ccID := Coefs.GetCoeffID(c)
			state[i-1].SetCoeffID(ccID)
			state = append(state[:i], state[i+1:]...)
			i--
		}
	}

	return state
}

func ConstantValue(v LinearExpression, Coefs CoeffTable) (*big.Int, bool) {
	if len(v) != 1 {
		return nil, false
	}
	cID, vID, visibility := v[0].Unpack()
	if !(vID == 0 && visibility == schema.Public) {
		return nil, false
	}
	return new(big.Int).Set(Coefs.GetCoeffsById(cID)), true
}

func (le *LazyPoseidonInputs) GetConstraintsNum() int {
	return ConstraintsMap[len(le.S)-3]
}

func (le *LazyPoseidonInputs) FetchLazy(j int, r1cs *R1CS, coefs CoeffTable) R1C {
	return FetchLazyConstraint(le.S, r1cs.LazyConsStaticR1CMap[le.GetType(coefs)], j, coefs)
}

func (le *LazyPoseidonInputs) GetLoc() int {
	return le.Loc
}

func (le *LazyPoseidonInputs) GetType(coefs CoeffTable) string {
	constantNum := 0
	targetStr := ""
	for i, s := range le.S {
		if v, is := ConstantValue(s, coefs); is {
			constantNum++
			targetStr += "-pos-" + strconv.Itoa(i) + "-val-" + v.String()
		}
	}
	return "poseidon-params-" + strconv.Itoa(len(le.S)) + "-constants-" + strconv.Itoa(constantNum) + targetStr
}

func (le *LazyPoseidonInputs) SetConsStaticR1CMapIfNotExists(r1cs *R1CS, table CoeffTable) error {
	if _, ok := r1cs.LazyConsStaticR1CMap[le.GetType(table)]; !ok {
		r1cs.LazyConsOriginInputMap[le.GetType(table)] = le
		r1cs.LazyConsStaticR1CMap[le.GetType(table)] = StaticPoseidonR1CS(le.V, table, le.S...)
	}
	return nil
}

func (le *LazyPoseidonInputs) GetShift(r1cs *R1CS, table CoeffTable) int {
	return GetShift(le.V, r1cs.LazyConsOriginInputMap[le.GetType(table)].(*LazyPoseidonInputs).V)
}

func (le *LazyPoseidonInputs) GetInitialIndex() int {
	return le.V[0].WireID() - le.GetConstraintsNum()
}

func (le *LazyPoseidonInputs) IsInput(j int, loc uint8) bool {
	// 2
	width := len(le.S)
	// 0, 1, 2, 3
	// j == 0 -> true
	// j == 3 -> true
	// j == 6 -> false
	if j%3 == 0 && j/3 < width && loc == 1 {
		return true
	}
	// s0, s1
	if j%3 == 0 && j/3 < width && loc == 2 {
		return true
	}
	// 0, 1, 2, 3
	// j == 2 -> true
	// j == 5 -> true
	// j == 8 -> false
	if j%3 == 2 && j/3 < width && loc == 2 {
		return true
	}

	return false
}
