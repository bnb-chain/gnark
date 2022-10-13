/*
Copyright © 2020 ConsenSys

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at

    http://www.apache.org/licenses/LICENSE-2.0

Unless required by applicable law or agreed to in writing, software
distributed under the License is distributed on an "AS IS" BASIS,
WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
See the License for the specific language governing permissions and
limitations under the License.
*/

// Package eddsa provides a ZKP-circuit function to verify a EdDSA signature.
package eddsa

import (
	"errors"
	"github.com/consensys/gnark-crypto/ecc"
	"github.com/consensys/gnark/frontend"
	"github.com/consensys/gnark/logger"
	"github.com/consensys/gnark/std/algebra/twistededwards"
	"github.com/consensys/gnark/std/hash"

	edwardsbls12377 "github.com/consensys/gnark-crypto/ecc/bls12-377/twistededwards"
	edwardsbls12381 "github.com/consensys/gnark-crypto/ecc/bls12-381/twistededwards"
	edwardsbls24315 "github.com/consensys/gnark-crypto/ecc/bls24-315/twistededwards"
	edwardsbn254 "github.com/consensys/gnark-crypto/ecc/bn254/twistededwards"
	edwardsbw6633 "github.com/consensys/gnark-crypto/ecc/bw6-633/twistededwards"
	edwardsbw6761 "github.com/consensys/gnark-crypto/ecc/bw6-761/twistededwards"
)

// PublicKey stores an eddsa public key (to be used in gnark circuit)
type PublicKey struct {
	A twistededwards.Point
}

// Signature stores a signature  (to be used in gnark circuit)
// An EdDSA signature is a tuple (R,S) where R is a point on the twisted Edwards curve
// and S a scalar. Since the base field of the twisted Edwards is Fr, the number of points
// N on the Edwards is < r+1+2sqrt(r)+2 (since the curve has 2 points of multiplicity 2).
// The subgroup l used in eddsa is <1/2N, so the reduction
// mod l ensures S < r, therefore there is no risk of overflow.
type Signature struct {
	R twistededwards.Point
	S frontend.Variable
}

type BatchStores struct {
	Sigs    []Signature
	Msgs    []frontend.Variable
	Pubkeys []PublicKey
	Flags   []frontend.Variable
}

var batchSize = 32

// CreateBatchStores will create a batch stores signature needs to be verified
func CreateBatchStores() *BatchStores {
	return &BatchStores{Sigs: make([]Signature, 0), Msgs: make([]frontend.Variable, 0), Pubkeys: make([]PublicKey, 0)}
}

// Verify verifies an eddsa signature using MiMC hash function
// cf https://en.wikipedia.org/wiki/EdDSA
func Verify(batch *BatchStores, curve twistededwards.Curve, sig Signature, msg frontend.Variable, pubKey PublicKey, flag frontend.Variable, hash hash.Hash) error {
	batch.Pubkeys = append(batch.Pubkeys, pubKey)
	batch.Msgs = append(batch.Msgs, msg)
	batch.Sigs = append(batch.Sigs, sig)
	batch.Flags = append(batch.Flags, flag)
	return nil
}

// Flush splits the Verify results into batches and then call batchVerfiy to the batches
// cf https://en.wikipedia.org/wiki/EdDSA
func Flush(batch *BatchStores, curve twistededwards.Curve, hash hash.Hash) error {
	i := 0
	for ; i+batchSize <= len(batch.Msgs); i += batchSize {
		err := BatchVerify(curve, batch.Sigs[i:i+batchSize], batch.Msgs[i:i+batchSize], batch.Pubkeys[i:i+batchSize], batch.Flags[i:i+batchSize], hash)
		if err != nil {
			return err
		}
	}

	if i+batchSize > len(batch.Msgs) {
		err := BatchVerify(curve, batch.Sigs[i:], batch.Msgs[i:], batch.Pubkeys[i:], batch.Flags[i:], hash)
		if err != nil {
			return err
		}
	}

	batch.Pubkeys = batch.Pubkeys[:0]
	batch.Msgs = batch.Msgs[:0]
	batch.Sigs = batch.Sigs[:0]

	return nil
}

// BatchVerify verifies an eddsa signature using MiMC hash function
// cf https://en.wikipedia.org/wiki/EdDSA
func BatchVerify(curve twistededwards.Curve, sig []Signature, msg []frontend.Variable, pubKey []PublicKey, flag []frontend.Variable, hash hash.Hash) error {

	hRAMs := make([]frontend.Variable, len(sig))
	for i := range hRAMs {
		hash.Reset()
		// compute H(R, A, M)
		hash.Write(sig[i].R.X)
		hash.Write(sig[i].R.Y)
		hash.Write(pubKey[i].A.X)
		hash.Write(pubKey[i].A.Y)
		hash.Write(msg[i])
		hRAMs[i] = hash.Sum()
	}

	var hRAMSum frontend.Variable = 0
	for i := range hRAMs {
		hRAMSum = curve.API().Add(hRAMSum, hRAMs[i])
	}

	var tRAM frontend.Variable = hRAMSum
	tRAMExp := make([]frontend.Variable, len(sig))
	tRAMExp[0] = 1
	for i := range tRAMExp {
		if i == 0 {
			continue
		}
		tRAMExp[i] = curve.API().Mul(tRAMExp[i-1], tRAM)
		tRAMExp[i] = curve.API().Select(flag[i], tRAMExp[i], 0) // for those flag is set to false, we do not add them into verification
	}

	base := twistededwards.Point{
		X: curve.Params().Base[0],
		Y: curve.Params().Base[1],
	}

	_R_APointsSum := twistededwards.Point{X: 0, Y: 1}
	points := make([]*twistededwards.Point, 0)
	coeffs := make([]frontend.Variable, 0)
	for i := range tRAMExp {
		ACoeff := curve.API().MulModP(tRAMExp[i], hRAMs[i], curve.Params().Order)
		points = append(points, &pubKey[i].A, &sig[i].R)
		coeffs = append(coeffs, ACoeff, tRAMExp[i])
	}
	_R_APointsSum = curve.MultiBaseScalarMulCached(points, coeffs)
	_R_APointsSum = curve.Neg(_R_APointsSum)

	var GCoeffSum frontend.Variable = 0
	var GCoeffArr = make([]frontend.Variable, 0)
	for i := range tRAMExp {
		GCoeffArr = append(GCoeffArr, tRAMExp[i], sig[i].S)
	}

	GCoeffSum = curve.API().MultiBigMulAndAddGetMod(curve.Params().Order, GCoeffArr...)
	GPointSum := curve.ScalarMul(base, GCoeffSum)
	Q := curve.Add(GPointSum, _R_APointsSum)
	curve.AssertIsOnCurve(Q)

	// [cofactor]*(lhs-rhs)
	log := logger.Logger()
	if !curve.Params().Cofactor.IsUint64() {
		err := errors.New("invalid cofactor")
		log.Err(err).Str("cofactor", curve.Params().Cofactor.String()).Send()
		return err
	}
	cofactor := curve.Params().Cofactor.Uint64()
	switch cofactor {
	case 4:
		Q = curve.Double(curve.Double(Q))
	case 8:
		Q = curve.Double(curve.Double(curve.Double(Q)))
	default:
		log.Warn().Str("cofactor", curve.Params().Cofactor.String()).Msg("curve cofactor is not implemented")
	}

	curve.API().AssertIsEqual(Q.X, 0)
	curve.API().AssertIsEqual(Q.Y, 1)

	return nil
}

// Assign is a helper to assigned a compressed binary public key representation into its uncompressed form
func (p *PublicKey) Assign(curveID ecc.ID, buf []byte) {
	ax, ay, err := parsePoint(curveID, buf)
	if err != nil {
		panic(err)
	}
	p.A.X = ax
	p.A.Y = ay
}

// Assign is a helper to assigned a compressed binary signature representation into its uncompressed form
func (s *Signature) Assign(curveID ecc.ID, buf []byte) {
	rx, ry, S, err := parseSignature(curveID, buf)
	if err != nil {
		panic(err)
	}
	s.R.X = rx
	s.R.Y = ry
	s.S = S
}

// parseSignature parses a compressed binary signature into uncompressed R.X, R.Y and S
func parseSignature(curveID ecc.ID, buf []byte) ([]byte, []byte, []byte, error) {

	var pointbn254 edwardsbn254.PointAffine
	var pointbls12381 edwardsbls12381.PointAffine
	var pointbls12377 edwardsbls12377.PointAffine
	var pointbw6761 edwardsbw6761.PointAffine
	var pointbls24315 edwardsbls24315.PointAffine
	var pointbw6633 edwardsbw6633.PointAffine

	switch curveID {
	case ecc.BN254:
		if _, err := pointbn254.SetBytes(buf[:32]); err != nil {
			return nil, nil, nil, err
		}
		a, b, err := parsePoint(curveID, buf)
		if err != nil {
			return nil, nil, nil, err
		}
		s := buf[32:]
		return a, b, s, nil
	case ecc.BLS12_381:
		if _, err := pointbls12381.SetBytes(buf[:32]); err != nil {
			return nil, nil, nil, err
		}
		a, b, err := parsePoint(curveID, buf)
		if err != nil {
			return nil, nil, nil, err
		}
		s := buf[32:]
		return a, b, s, nil
	case ecc.BLS12_377:
		if _, err := pointbls12377.SetBytes(buf[:32]); err != nil {
			return nil, nil, nil, err
		}
		a, b, err := parsePoint(curveID, buf)
		if err != nil {
			return nil, nil, nil, err
		}
		s := buf[32:]
		return a, b, s, nil
	case ecc.BW6_761:
		if _, err := pointbw6761.SetBytes(buf[:48]); err != nil {
			return nil, nil, nil, err
		}
		a, b, err := parsePoint(curveID, buf)
		if err != nil {
			return nil, nil, nil, err
		}
		s := buf[48:]
		return a, b, s, nil
	case ecc.BLS24_315:
		if _, err := pointbls24315.SetBytes(buf[:32]); err != nil {
			return nil, nil, nil, err
		}
		a, b, err := parsePoint(curveID, buf)
		if err != nil {
			return nil, nil, nil, err
		}
		s := buf[32:]
		return a, b, s, nil
	case ecc.BW6_633:
		if _, err := pointbw6633.SetBytes(buf[:40]); err != nil {
			return nil, nil, nil, err
		}
		a, b, err := parsePoint(curveID, buf)
		if err != nil {
			return nil, nil, nil, err
		}
		s := buf[40:]
		return a, b, s, nil
	default:
		panic("not implemented")
	}
}

// parsePoint parses a compressed binary point into uncompressed P.X and P.Y
func parsePoint(curveID ecc.ID, buf []byte) ([]byte, []byte, error) {
	var pointbn254 edwardsbn254.PointAffine
	var pointbls12381 edwardsbls12381.PointAffine
	var pointbls12377 edwardsbls12377.PointAffine
	var pointbw6761 edwardsbw6761.PointAffine
	var pointbls24315 edwardsbls24315.PointAffine
	var pointbw6633 edwardsbw6633.PointAffine
	switch curveID {
	case ecc.BN254:
		if _, err := pointbn254.SetBytes(buf[:32]); err != nil {
			return nil, nil, err
		}
		a := pointbn254.X.Bytes()
		b := pointbn254.Y.Bytes()
		return a[:], b[:], nil
	case ecc.BLS12_381:
		if _, err := pointbls12381.SetBytes(buf[:32]); err != nil {
			return nil, nil, err
		}
		a := pointbls12381.X.Bytes()
		b := pointbls12381.Y.Bytes()
		return a[:], b[:], nil
	case ecc.BLS12_377:
		if _, err := pointbls12377.SetBytes(buf[:32]); err != nil {
			return nil, nil, err
		}
		a := pointbls12377.X.Bytes()
		b := pointbls12377.Y.Bytes()
		return a[:], b[:], nil
	case ecc.BW6_761:
		if _, err := pointbw6761.SetBytes(buf[:48]); err != nil {
			return nil, nil, err
		}
		a := pointbw6761.X.Bytes()
		b := pointbw6761.Y.Bytes()
		return a[:], b[:], nil
	case ecc.BLS24_315:
		if _, err := pointbls24315.SetBytes(buf[:32]); err != nil {
			return nil, nil, err
		}
		a := pointbls24315.X.Bytes()
		b := pointbls24315.Y.Bytes()
		return a[:], b[:], nil
	case ecc.BW6_633:
		if _, err := pointbw6633.SetBytes(buf[:40]); err != nil {
			return nil, nil, err
		}
		a := pointbw6633.X.Bytes()
		b := pointbw6633.Y.Bytes()
		return a[:], b[:], nil
	default:
		panic("not implemented")
	}
}
