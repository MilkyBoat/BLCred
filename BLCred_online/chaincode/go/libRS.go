package main

import (
	// "bytes"
	"crypto/md5"
	// "encoding/binary"
	// "encoding/json"
	"golang.org/x/crypto/bn256"
	"math/big"
	"math/rand"
	"time"
)

// RS class
type RS struct {
	P *big.Int
}

// RSSK sk x, y *big.Int
type RSSK struct {
	x *big.Int
	y []*big.Int
}

// // Bytes : encode RSSK to []byte
// func (rssk *RSSK) Bytes() []byte {
// 	buf := bytes.NewBuffer([]byte{})
// 	bx := rssk.x.Bytes()
// 	// binary.Write(buf, binary.BigEndian, len(bx))
// 	binary.Write(buf, binary.BigEndian, bx)
// 	// binary.Write(buf, binary.BigEndian, len(rssk.y))
// 	for _, v := range rssk.y {
// 		by := v.Bytes()
// 		// binary.Write(buf, binary.BigEndian, len(by))
// 		binary.Write(buf, binary.BigEndian, by)
// 	}
// 	return buf.Bytes()
// }

// // FromBytes : decode RSSK from []byte
// //	buf:	[]byte to decode
// //	bits:	int, the bit length of big number used in RSSK, same with big prime P,
// //			get it with: len(p.Bytes()), in BLCred project, p was set 16bits as default
// //	leny:	int, amount of elements in y
// func (rssk *RSSK) FromBytes(buf []byte, bits int, leny int) bool {
// 	if len(buf) < bits*(leny+1) {
// 		return false
// 	}
// 	rssk.x.SetBytes(buf[:bits])
// 	for i := 1; i <= leny; i++ {
// 		n := big.NewInt(0).SetBytes(buf[bits*i : bits*(i+1)])
// 		rssk.y = append(rssk.y, n)
// 	}
// 	return true
// }

// RSVK vk X, _X, Y, _Y, Z *bn256.G1 and *bn256.G2
type RSVK struct {
	X  *bn256.G1
	_X *bn256.G2
	Y  []*bn256.G1
	_Y []*bn256.G2
	Z  map[int]*bn256.G1
}

// // Bytes : encode RSVK to []byte
// func (rsvk *RSVK) Bytes() []byte {
// 	buf := bytes.NewBuffer([]byte{})
// 	binary.Write(buf, binary.BigEndian, rsvk.X.Marshal())
// 	binary.Write(buf, binary.BigEndian, rsvk._X.Marshal())
// 	for _, v := range rsvk.Y {
// 		binary.Write(buf, binary.BigEndian, v.Marshal())
// 	}
// 	for _, v := range rsvk._Y {
// 		binary.Write(buf, binary.BigEndian, v.Marshal())
// 	}
// 	binary.Write(buf, binary.BigEndian)
// 	return buf.Bytes()
// }

// // FromBytes : decode RSVK from []byte
// //	buf:	[]byte to decode
// //	bits:	int, the bit length of big number used in RSVK, same with big prime P,
// //			get it with: len(p.Bytes()), in BLCred project, p was set 16bits as default
// //	leny:	int, amount of elements in y
// func (rsvk *RSVK) FromBytes(buf []byte, bits int, leny int) bool {
// 	if len(buf) < bits*(leny+1) {
// 		return false
// 	}
// 	rsvk.X.SetBytes(buf[:bits])
// 	for i := 1; i <= leny; i++ {
// 		n := big.NewInt(0).SetBytes(buf[bits*i : bits*(i+1)])
// 		rsvk.Y = append(rsvk.Y, n)
// 	}
// 	return true
// }

// SIGMA s1, s2, s11, s21
type SIGMA struct {
	sigma1  *bn256.G1
	sigma2  *bn256.G1
	sigma11 *bn256.G2
	sigma21 *bn256.G2
}

// Init (p)
func (rs *RS) Init(_p *big.Int) {
	rs.P = _p
}

// Keygen (n)
func (rs *RS) Keygen(n int) (RSSK, RSVK) {

	r := rand.New(rand.NewSource(0))
	r.Seed(time.Now().UnixNano())
	x := big.NewInt(0).Rand(r, rs.P)
	X := new(bn256.G1).ScalarBaseMult(x)
	_X := new(bn256.G2).ScalarBaseMult(x)
	y := make([]*big.Int, n)
	Y := make([]*bn256.G1, n)
	_Y := make([]*bn256.G2, n)
	Z := make(map[int]*bn256.G1)

	for i := 0; i < n; i++ {
		y[i] = big.NewInt(0).Rand(r, rs.P)
		Y[i] = new(bn256.G1).ScalarBaseMult(y[i])
		_Y[i] = new(bn256.G2).ScalarBaseMult(y[i])
	}
	for i := 0; i < n; i++ {
		for j := 0; j < i; j++ {
			t := big.NewInt(0).Mul(y[i], y[j])
			Z[(i+1)*n+j+1] = new(bn256.G1).ScalarBaseMult(t)
		}
	}

	return RSSK{x, y}, RSVK{X, _X, Y, _Y, Z}
}

// Sign (sk, m)
func (rs *RS) Sign(sk RSSK, m []string) SIGMA {

	_r := rand.New(rand.NewSource(time.Now().UnixNano()))
	hash := md5.New()
	r := big.NewInt(0).Rand(_r, rs.P)
	sigma1 := new(bn256.G2).ScalarBaseMult(r)
	e := sk.x
	for i := range sk.y {
		mInt := big.NewInt(0).SetBytes(hash.Sum([]byte(m[i])))
		e.Add(e, big.NewInt(0).Mul(mInt, sk.y[i]))
	}
	sigma2 := new(bn256.G2).ScalarMult(sigma1, e)
	g11 := new(bn256.G1).ScalarBaseMult(big.NewInt(0))
	g12 := new(bn256.G1).ScalarBaseMult(big.NewInt(0))
	return SIGMA{g11, g12, sigma1, sigma2}
}

// Derive (vk, sigma, D, m)
func (rs *RS) Derive(vk RSVK, sigma SIGMA, D []bool, m []string) SIGMA {
	n := len(vk.Y)
	lenD := 0
	for i := 0; i < n; i++ {
		if D[i] {
			lenD++
		}
	}
	hash := md5.New()
	_r := rand.New(rand.NewSource(time.Now().UnixNano()))
	t := big.NewInt(0).Rand(_r, rs.P)
	r := big.NewInt(0).Rand(_r, rs.P)
	sigma11 := new(bn256.G1).ScalarBaseMult(big.NewInt(0))
	sigma21 := new(bn256.G1).ScalarBaseMult(big.NewInt(0))
	if lenD != n {
		msgs := make([]*big.Int, n)
		for i := 0; i < n; i++ {
			msgs[i] = big.NewInt(0).SetBytes(hash.Sum([]byte(m[i])))
		}

		sigma11.Add(sigma11, new(bn256.G1).ScalarBaseMult(t))
		for i, v := range D {
			if v {
				sigma21.Add(sigma21, vk.Y[i])
			} else {
				sigma11.Add(sigma11, new(bn256.G1).ScalarMult(vk.Y[i], msgs[i]))
			}
		}
		sigma21.ScalarMult(sigma21, t)
		for j, v := range D {
			if !v {
				t := new(bn256.G1).ScalarBaseMult(big.NewInt(0))
				for i, v1 := range D {
					if v1 {
						t.Add(t, vk.Z[max(i+1, j+1)*n+min(i+1, j+1)])
					}
				}
				t.ScalarMult(t, msgs[j])
				sigma21.Add(sigma21, t)
			}
		}
	} else {
		sigma11.ScalarBaseMult(t)
		for i := 0; i < n; i++ {
			sigma21.Add(sigma21, vk.Y[i])
		}
		sigma21.ScalarMult(sigma21, t)
	}
	sigma12 := new(bn256.G2).ScalarMult(sigma.sigma11, r)
	sigma22 := new(bn256.G2).ScalarMult(sigma.sigma11, t)
	sigma22.Add(sigma.sigma21, sigma22)
	sigma22.ScalarMult(sigma22, r)

	return SIGMA{sigma11, sigma21, sigma12, sigma22}
}

// Verify (X, Y, Z, sigma, D, m)
func (rs *RS) Verify(vk RSVK, sigma SIGMA, D []bool, m []string) bool {
	expr1_1 := new(bn256.G1).Add(vk.X, sigma.sigma1)
	expr1_2 := new(bn256.G2).ScalarBaseMult(big.NewInt(0))
	hash := md5.New()
	for i, v := range D {
		if v {
			msg := big.NewInt(0).SetBytes(hash.Sum([]byte(m[i])))
			expr1_1.Add(expr1_1, new(bn256.G1).ScalarMult(vk.Y[i], msg))
			expr1_2.Add(expr1_2, vk._Y[i])
		}
	}
	g1 := new(bn256.G1).ScalarBaseMult(big.NewInt(1))
	g2 := new(bn256.G2).ScalarBaseMult(big.NewInt(1))
	expr2_1 := bn256.Pair(expr1_1, sigma.sigma11).String() == bn256.Pair(g1, sigma.sigma21).String()
	expr2_2 := bn256.Pair(sigma.sigma1, expr1_2).String() == bn256.Pair(sigma.sigma2, g2).String()
	// println(expr2_1, expr2_2)
	return expr2_1 && expr2_2
}

func max(a int, b int) int {
	if a > b {
		return a
	}
	return b
}

func min(a int, b int) int {
	if a > b {
		return b
	}
	return a
}

// D2string : encode a bool set to string set
func D2string(D []bool) string {
	s := ""
	for _, v := range D {
		if v == true {
			s += "1"
		} else {
			s += "0"
		}
	}
	return s
}

// String2D : decode a string set to bool set
func String2D(s string) []bool {
	D := []bool{}
	for i := 0; i < len(s); i++ {
		if s[i] == '1' {
			D = append(D, true)
		} else if s[i] == '0' {
			D = append(D, false)
		} else {
			panic("illegal string")
		}
	}
	return D
}

func rsTest() {
	m := []string{"a22", "b33", "nezuko", "kawaii", "hhh", "lol2333"}
	D := []bool{true, false, true, true, false, false}
	p, _ := big.NewInt(0).SetString("1020831745583176952747469275099", 10)
	rs := new(RS)
	rs.Init(p)
	sk, vk := rs.Keygen(len(m))
	// println(sk, vk)
	sigma := rs.Sign(sk, m)
	sigma = rs.Derive(vk, sigma, D, m)
	// println(sigma)
	verify := rs.Verify(vk, sigma, D, m)
	println("RS test result: ", verify)
}
