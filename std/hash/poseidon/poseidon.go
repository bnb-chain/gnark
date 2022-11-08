package poseidon

import (
	"math/big"

	"github.com/consensys/gnark/frontend"
)

// Add round constants
func arc(api frontend.API, state []frontend.Variable, C []*big.Int, t, offset int) {
	for i := 0; i < t; i++ {
		state[i] = api.Add(state[i], C[offset+i])
	}
}

// power 5 as s-box for full state
func sboxFull(api frontend.API, state []frontend.Variable, t int) {
	for i := 0; i < t; i++ {
		r := api.Mul(state[i], state[i])
		r = api.Mul(r, r)
		state[i] = api.Mul(state[i], r)
	}
}

// power 5 as s-box
func sbox(api frontend.API, x frontend.Variable) frontend.Variable {
	r := api.Mul(x, x)
	r = api.Mul(r, r)
	return api.Mul(x, r)
}

// Matrix vector multiplication
func mix(api frontend.API, state []frontend.Variable, M [][]*big.Int, t int) []frontend.Variable {
	newState := make([]frontend.Variable, t)

	for i := 0; i < t; i++ {
		newState[i] = big.NewInt(0)
		for j := 0; j < t; j++ {
			newState[i] = api.Add(newState[i], api.Mul(M[j][i], state[j]))
		}
	}
	return newState
}

func permutation(api frontend.API, state []frontend.Variable) []frontend.Variable {
	// Minimum length of state = nInput + nOutput = 2
	t := len(state)
	index := t - 2
	RP := rp[index]
	C := c[index]
	M := m[index]
	S := s[index]
	P := p[index]

	// 1. Pre-step to the first-half of full rounds: add round constant for round=0
	arc(api, state, C, t, 0)
	
	// 2. First-half of full rounds starting at roundNumber = 1 except last round
	for i:=0; i< rf/2-1; i++ {
		sboxFull(api, state, t)
		arc(api, state, C, t, (i+1)*t)
		state = mix(api, state, M, t)
	}
	
	// 3. Last round of first-half of full rounds
	sboxFull(api, state, t)
	arc(api, state, C, t, (rf/2)*t)
	state = mix(api, state, P, t)
	
	// 4. Partial rounds
	for i := 0; i < RP; i++ {
		state[0] = sbox(api, state[0])
		state[0] = api.Add(state[0], C[(rf/2+1)*t+i])
		// S[i] is a vector of [t*2-1] elements where first t elements are used to compute state[0]
		// and the remaining elements starting at [t] are used to compute state[1,..,t-1]
		offset := (t*2-1)*i
		newState0 := frontend.Variable(0)
		for j := 0; j < len(state); j++ {
			newState0 = api.Add(newState0, api.Mul(state[j], S[offset+j]))
		}
		offset += t - 1
		for k := 1; k < t; k++ {
			state[k] = api.Add(state[k], api.Mul(state[0], S[offset + k]))
		}
		state[0] = newState0
	}
	
	// 5. Second-half of full rounds except last round
	for i:=0; i < rf/2-1; i++ {
		sboxFull(api, state, t)
		arc(api, state, C, t, (rf/2+1)*t+RP+i*t)
		state = mix(api, state, M, t)
	}
	
	// 6. Last round of the second-half of full rounds
	sboxFull(api, state, t)
	state = mix(api, state, M, t)
	return state
}

func Poseidon(api frontend.API, input ...frontend.Variable) frontend.Variable {
	inputLength := len(input)
	// No support for hashing null input
	if inputLength == 0 {
		panic("Not supported input size")
	}

	const maxLength = 12
	state := make([]frontend.Variable, maxLength+1)
	state[0] = frontend.Variable(0)
	startIndex := 0
	lastIndex := 0

	// Make a hash chain of the input if its length > maxLength
	if inputLength > maxLength {
		count := inputLength / maxLength
		for i := 0; i < count; i++ {
			lastIndex = (i + 1) * maxLength
			copy(state[1:], input[startIndex:lastIndex])
			state = permutation(api, state)
			startIndex = lastIndex
		}
	}

	// For the remaining part of the input OR if 2 <= inputLength <= 12
	if lastIndex < inputLength {
		lastIndex = inputLength
		remainigLength := lastIndex - startIndex
		copy(state[1:], input[startIndex:lastIndex])
		state = permutation(api, state[:remainigLength+1])
	}
	return state[0]
}
