package poseidon

import (
	"github.com/consensys/gnark/backend/hint"
	"github.com/consensys/gnark/frontend"
	"github.com/consensys/gnark/frontend/compiled"
	"github.com/consensys/gnark/std/hash/poseidon/constants"
)

// power 5 as s-box
func sbox(api frontend.API, x frontend.Variable) frontend.Variable {
	r := api.Mul(x, x)
	r = api.Mul(r, r)
	return api.Mul(r, x)
}

// MDS matrix multiply mds * state
func mix(api frontend.API, state []frontend.Variable) []frontend.Variable {
	width := len(state)
	index := width - 3
	newState := make([]frontend.Variable, width)

	for i := 0; i < width; i++ {
		acc := frontend.Variable(0)
		for j := 0; j < width; j++ {
			mul := api.Mul(constants.MDS[index][i][j], state[j])
			acc = api.Add(acc, mul)
		}
		newState[i] = acc
	}
	return newState
}

func fullRounds(api frontend.API, state []frontend.Variable, roundCounter *int) []frontend.Variable {
	width := len(state)
	index := width - 3
	rf := constants.RF / 2
	for i := 0; i < rf; i++ {
		for j := 0; j < width; j++ {
			// Add round constants
			state[j] = api.Add(state[j], constants.RC[index][*roundCounter])
			*roundCounter += 1
			// Apply full s-box
			state[j] = sbox(api, state[j])
		}
		// Apply mix layer
		state = mix(api, state)
	}
	return state
}

func partialRounds(api frontend.API, state []frontend.Variable, roundCounter *int) []frontend.Variable {
	width := len(state)
	index := width - 3
	for i := 0; i < constants.RP[index]; i++ {
		for j := 0; j < width; j++ {
			// Add round constants
			state[j] = api.Add(state[j], constants.RC[index][*roundCounter])
			*roundCounter += 1
		}
		// Apply single s-box
		state[0] = sbox(api, state[0])
		// Apply mix layer
		state = mix(api, state)
	}
	return state
}

func permutation(api frontend.API, state []frontend.Variable) []frontend.Variable {
	roundCounter := 0
	state = fullRounds(api, state, &roundCounter)
	state = partialRounds(api, state, &roundCounter)
	state = fullRounds(api, state, &roundCounter)
	return state
}

func preHandleData(api frontend.API, data ...frontend.Variable) []frontend.Variable {
	// if all constants, skipped
	constantCount := 0
	for i := range data {
		if _, isConstant := api.Compiler().ConstantValue(data[i]); isConstant {
			constantCount++
		}
	}
	if constantCount == len(data) {
		return data
	}

	// get the self variables by hint, and make sure it is equal to data[i]
	for i := range data {
		self, err := api.Compiler().NewHint(hint.Self, 1, data[i])
		if err != nil {
			panic(err)
		}
		api.AssertIsEqual(self[0], data[i])
		data[i] = self[0]
	}
	return data
}

func Poseidon(api frontend.API, data ...frontend.Variable) frontend.Variable {
	data = preHandleData(api, data...)
	// we record 2 params first, then lets see if we can record multi params and solve
	t := len(data) + 1
	if t < 3 || t > 13 {
		panic("Not supported input size")
	}
	vInternal := api.AddInternalVariableWithLazy(compiled.GetConstraintsNum(data, api))
	api.AddLazyPoseidon(vInternal, data...)
	state := make([]frontend.Variable, t)
	state[0] = frontend.Variable(0)
	copy(state[1:], data)
	state = permutation(api, state)
	return state[0]
}
