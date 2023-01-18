package common

import (
	"github.com/consensys/gnark/std/gkr/hash"

	"github.com/consensys/gnark-crypto/ecc/bn254/fr"
)

// GetChallenge returns a interaction challenge
func GetChallenge(challengeSeed []fr.Element) fr.Element {
	return hash.MimcHash(challengeSeed)
}
