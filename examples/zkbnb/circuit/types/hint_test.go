package types

type HintConstraints struct {
	A Variable
	B Variable
	C Variable
}

func (circuit HintConstraints) Define(api API) error {
	hashVals, err := api.Compiler().NewHint(Keccak256, 1, circuit.A, circuit.B)
	if err != nil {
		return err
	}
	api.AssertIsEqual(hashVals[0], circuit.C)
	return nil
}
