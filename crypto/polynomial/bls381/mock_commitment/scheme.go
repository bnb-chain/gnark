// Copyright 2020 ConsenSys Software Inc.
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

// Code generated by gnark DO NOT EDIT

package mockcommitment

import (
	"io"

	"github.com/consensys/gnark/crypto/polynomial"
	"github.com/consensys/gnark/crypto/polynomial/bls381"
)

// Scheme mock commitment, useful for testing polynomial based IOP
// like PLONK, where the scheme should not depend on which polynomial commitment scheme
// is used.
type Scheme struct{}

// WriteTo panics
func (s *Scheme) WriteTo(w io.Writer) (n int64, err error) {
	return 0, nil
}

// ReadFrom panics
func (s *Scheme) ReadFrom(r io.Reader) (n int64, err error) {
	return 0, nil
}

// Commit returns nil
func (s *Scheme) Commit(p polynomial.Polynomial) polynomial.Digest {
	res := &MockDigest{Digest: p.(bls381.Poly)}
	return res
}

// Open computes an opening proof of _p at _val.
// Returns a MockProof, which is an empty interface.
func (s *Scheme) Open(_val interface{}, _p polynomial.Polynomial) polynomial.OpeningProof { //Open(p *bls381.Poly, val *fr.Element) *MockProof {
	return &MockProof{}
}

// Verify mock implementation of verify
func (s *Scheme) Verify(d polynomial.Digest, p polynomial.OpeningProof, v interface{}) bool {
	return true
}

// BatchOpenSinglePoint computes a batch opening proof for _p at
// a single point.
// Returns an empty interface.
func (s *Scheme) BatchOpenSinglePoint(_val, challenge interface{}, _p ...polynomial.Polynomial) polynomial.BatchOpeningProofSinglePoint { //Open(p *bls381.Poly, val *fr.Element) *MockProof {
	return &MockProof{}
}

// BatchVerifySinglePoint computes a batch opening proof for
func (s *Scheme) BatchVerifySinglePoint(_val, challenge interface{}, d ...polynomial.Digest) bool {
	return true
}
