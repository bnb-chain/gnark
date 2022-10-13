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

package twistededwards

import (
	"github.com/consensys/gnark/frontend"
)

// neg computes the negative of a point in SNARK coordinates
func (p *Point) neg(api frontend.API, p1 *Point) *Point {
	p.X = api.Neg(p1.X)
	p.Y = p1.Y
	return p
}

// assertIsOnCurve checks if a point is on the reduced twisted Edwards curve
// a*x² + y² = 1 + d*x²*y².
func (p *Point) assertIsOnCurve(api frontend.API, curve *CurveParams) {

	xx := api.Mul(p.X, p.X)
	yy := api.Mul(p.Y, p.Y)
	axx := api.Mul(xx, curve.A)
	lhs := api.Add(axx, yy)

	dxx := api.Mul(xx, curve.D)
	dxxyy := api.Mul(dxx, yy)
	rhs := api.Add(dxxyy, 1)

	api.AssertIsEqual(lhs, rhs)

}

// add Adds two points on a twisted edwards curve (eg jubjub)
// p1, p2, c are respectively: the point to add, a known base point, and the parameters of the twisted edwards curve
func (p *Point) add(api frontend.API, p1, p2 *Point, curve *CurveParams) *Point {

	// u = (x1 + y1) * (x2 + y2)
	u1 := api.Mul(p1.X, curve.A)
	u1 = api.Sub(p1.Y, u1)
	u2 := api.Add(p2.X, p2.Y)
	u := api.Mul(u1, u2)

	// v0 = x1 * y2
	v0 := api.Mul(p2.Y, p1.X)

	// v1 = x2 * y1
	v1 := api.Mul(p2.X, p1.Y)

	// v2 = d * v0 * v1
	v2 := api.Mul(curve.D, v0, v1)

	// x = (v0 + v1) / (1 + v2)
	p.X = api.Add(v0, v1)
	p.X = api.DivUnchecked(p.X, api.Add(1, v2))

	// y = (u + a * v0 - v1) / (1 - v2)
	p.Y = api.Mul(curve.A, v0)
	p.Y = api.Sub(p.Y, v1)
	p.Y = api.Add(p.Y, u)
	p.Y = api.DivUnchecked(p.Y, api.Sub(1, v2))

	return p
}

// double doubles a points in SNARK coordinates
func (p *Point) double(api frontend.API, p1 *Point, curve *CurveParams) *Point {

	u := api.Mul(p1.X, p1.Y)
	v := api.Mul(p1.X, p1.X)
	w := api.Mul(p1.Y, p1.Y)

	n1 := api.Mul(2, u)
	av := api.Mul(v, curve.A)
	n2 := api.Sub(w, av)
	d1 := api.Add(w, av)
	d2 := api.Sub(2, d1)

	p.X = api.DivUnchecked(n1, d1)
	p.Y = api.DivUnchecked(n2, d2)

	return p
}

// scalarMul computes the scalar multiplication of a point on a twisted Edwards curve
// p1: base point (as snark point)
// curve: parameters of the Edwards curve
// scal: scalar as a SNARK constraint
// Standard left to right double and add
func (p *Point) scalarMul(api frontend.API, p1 *Point, scalar frontend.Variable, curve *CurveParams, endo ...*EndoParams) *Point {
	if len(endo) == 1 && endo[0] != nil {
		// use glv
		return p.scalarMulGLV(api, p1, scalar, curve, endo[0])
	}

	// first unpack the scalar
	b := api.ToBinary(scalar)

	res := Point{}
	tmp := Point{}
	A := Point{}
	B := Point{}

	A.double(api, p1, curve)
	B.add(api, &A, p1, curve)

	n := len(b) - 1
	res.X = api.Lookup2(b[n], b[n-1], 0, A.X, p1.X, B.X)
	res.Y = api.Lookup2(b[n], b[n-1], 1, A.Y, p1.Y, B.Y)

	for i := n - 2; i >= 1; i -= 2 {
		res.double(api, &res, curve).
			double(api, &res, curve)
		tmp.X = api.Lookup2(b[i], b[i-1], 0, A.X, p1.X, B.X)
		tmp.Y = api.Lookup2(b[i], b[i-1], 1, A.Y, p1.Y, B.Y)
		res.add(api, &res, &tmp, curve)
	}

	if n%2 == 0 {
		res.double(api, &res, curve)
		tmp.add(api, &res, p1, curve)
		res.X = api.Select(b[0], tmp.X, res.X)
		res.Y = api.Select(b[0], tmp.Y, res.Y)
	}

	p.X = res.X
	p.Y = res.Y

	return p
}

// doubleBaseScalarMul computes s1*P1+s2*P2
// where P1 and P2 are points on a twisted Edwards curve
// and s1, s2 scalars.
func (p *Point) doubleBaseScalarMul(api frontend.API, p1, p2 *Point, s1, s2 frontend.Variable, curve *CurveParams) *Point {

	// first unpack the scalars
	b1 := api.ToBinary(s1)
	b2 := api.ToBinary(s2)

	res := Point{}
	tmp := Point{}
	sum := Point{}
	sum.add(api, p1, p2, curve)

	n := len(b1)
	res.X = api.Lookup2(b1[n-1], b2[n-1], 0, p1.X, p2.X, sum.X)
	res.Y = api.Lookup2(b1[n-1], b2[n-1], 1, p1.Y, p2.Y, sum.Y)

	for i := n - 2; i >= 0; i-- {
		res.double(api, &res, curve)
		tmp.X = api.Lookup2(b1[i], b2[i], 0, p1.X, p2.X, sum.X)
		tmp.Y = api.Lookup2(b1[i], b2[i], 1, p1.Y, p2.Y, sum.Y)
		res.add(api, &res, &tmp, curve)
	}

	p.X = res.X
	p.Y = res.Y

	return p
}

// doubleBaseScalarMulCached computes s1*P1+s2*P2
// where P1 and P2 are points on a twisted Edwards curve
// and s1, s2 scalars.
func (p *Point) doubleBaseScalarMulCached(api frontend.API, p1, p2 *Point, s1, s2 frontend.Variable, curve *CurveParams) *Point {

	// first unpack the scalars
	b1 := api.ToBinary(s1)
	b2 := api.ToBinary(s2)
	n := len(b1)

	base1Arrays := make([]*Point, 8)
	base2Arrays := make([]*Point, 8)
	sumBase1Arrays := make([]*Point, 8)
	sumBase2Arrays := make([]*Point, 8)

	base1Arrays[0] = p1
	base2Arrays[0] = p2
	for i := 1; i < len(base1Arrays); i++ {
		base1Arrays[i] = new(Point).double(api, base1Arrays[i-1], curve)
		base2Arrays[i] = new(Point).double(api, base1Arrays[i-1], curve)
	}

	for i := 0; i < len(base1Arrays)-1; i += 2 {
		sum := Point{}
		sum.add(api, base1Arrays[i], base1Arrays[i+1], curve)
		sumBase1Arrays[i] = &sum
		sumBase1Arrays[i+1] = &sum
	}

	for i := 0; i < len(base1Arrays)-1; i += 2 {
		sum := Point{}
		sum.add(api, base2Arrays[i], base2Arrays[i+1], curve)
		sumBase2Arrays[i] = &sum
		sumBase2Arrays[i+1] = &sum
	}

	// 00000001 - ....
	// 1 - 2 - 4 - 8 - 16 - 32 - 64 - 128
	// 3 - 12 - 48 - 192

	//  8 doubles + 16 lookup-2s + 8 adds

	//  8 doubles ( every 8, should / 32 ) 0.25 doubles
	//  4 adds (every 8, should / 32) 0.125 adds
	//  16 lookup-2s + 8 adds + 8 doubles ( every batch, should / batch size )

	res := Point{0, 1}

	for i := n / 8; i >= 0; i-- {

		for j := 0; j < 7; j += 2 {
			if i*8+j+1 >= 254 {
				continue
			}
			b11 := b1[i*8+j]
			b12 := b1[i*8+j+1]

			tmp1 := Point{}
			tmp1.X = api.Lookup2(b11, b12, 0, base1Arrays[j].X, base1Arrays[j+1].X, sumBase1Arrays[j].X)
			tmp1.Y = api.Lookup2(b11, b12, 1, base1Arrays[j].Y, base1Arrays[j+1].Y, sumBase1Arrays[j].Y)
			res.add(api, &res, &tmp1, curve)

			b21 := b2[i*8+j]
			b22 := b2[i*8+j+1]

			tmp2 := Point{}
			tmp2.X = api.Lookup2(b21, b22, 0, base2Arrays[j].X, base2Arrays[j+1].X, sumBase2Arrays[j].X)
			tmp2.Y = api.Lookup2(b21, b22, 1, base2Arrays[j].Y, base2Arrays[j+1].Y, sumBase2Arrays[j].Y)

			res.add(api, &res, &tmp2, curve)
		}

		for k := 0; k < 8 && i != 0; k++ {
			res.double(api, &res, curve)
		}
	}

	p.X = res.X
	p.Y = res.Y
	return p
}

func prepareBinaryAndSumCache(api frontend.API, p *Point, s frontend.Variable, curve *CurveParams) (int, []frontend.Variable, []*Point, []*Point) {
	// first unpack the scalars
	b1 := api.ToBinary(s)
	n := len(b1)

	base1Arrays := make([]*Point, 8)
	sumBase1Arrays := make([]*Point, 8)

	base1Arrays[0] = p

	for i := 1; i < len(base1Arrays); i++ {
		base1Arrays[i] = new(Point).double(api, base1Arrays[i-1], curve)
	}

	for i := 0; i < len(base1Arrays)-1; i += 2 {
		sum := Point{}
		sum.add(api, base1Arrays[i], base1Arrays[i+1], curve)
		sumBase1Arrays[i] = &sum
		sumBase1Arrays[i+1] = &sum
	}

	return n, b1, base1Arrays, sumBase1Arrays
}

// multiBaseScalarMulCached computes s1*P1+s2*P2+s3*P3...+sn*Pn
func (p *Point) multiBaseScalarMulCached(api frontend.API, ps []*Point, ss []frontend.Variable, curve *CurveParams) *Point {

	// first unpack the scalars
	var n = 0
	binaryCaches := make([][]frontend.Variable, len(ps))
	sumCaches := make([][]*Point, len(ps))
	baseCaches := make([][]*Point, len(ps))
	for i := range ps {
		q, binaryCache, baseCache, sumCache := prepareBinaryAndSumCache(api, ps[i], ss[i], curve)
		binaryCaches[i] = binaryCache
		sumCaches[i] = sumCache
		baseCaches[i] = baseCache
		n = q
	}

	// 00000001 - ....
	// 1 - 2 - 4 - 8 - 16 - 32 - 64 - 128
	// 3 - 12 - 48 - 192

	//  8 doubles + 16 lookup-2s + 8 adds

	//  8 doubles ( every 8, should / 32 ) 0.25 doubles
	//  4 adds (every 8, should / 32) 0.125 adds
	//  16 lookup-2s + 8 adds + 8 doubles ( every batch, should / batch size )

	res := Point{0, 1}

	for i := n / 8; i >= 0; i-- {

		for j := 0; j < 7; j += 2 {
			if i*8+j+1 >= 254 {
				continue
			}

			for k := range binaryCaches {
				b11 := binaryCaches[k][i*8+j]
				b12 := binaryCaches[k][i*8+j+1]

				tmp1 := Point{}
				tmp1.X = api.Lookup2(b11, b12, 0, baseCaches[k][j].X, baseCaches[k][j+1].X, sumCaches[k][j].X)
				tmp1.Y = api.Lookup2(b11, b12, 1, baseCaches[k][j].Y, baseCaches[k][j+1].Y, sumCaches[k][j].Y)
				res.add(api, &res, &tmp1, curve)
			}
		}

		for k := 0; k < 8 && i != 0; k++ {
			res.double(api, &res, curve)
		}
	}

	p.X = res.X
	p.Y = res.Y
	return p
}
