package main

import (
	"crypto/md5"
	"golang.org/x/crypto/bn256"
	"math/big"
	"math/rand"
	"time"
)

// RS class
type RS struct {
	P         *big.Int
	MaxSetLen int
}

// Init (p)
func (rs *RS) Init(_p *big.Int) {
	rs.P = _p
	rs.MaxSetLen = 100
}

// Keygen ()
func (rs *RS) Keygen(n int) (*big.Int, *bn256.G1, []*big.Int, []*bn256.G1, []*bn256.G2, map[int]*bn256.G1) {

	r := rand.New(rand.NewSource(0))
	r.Seed(time.Now().UnixNano())
	x := big.NewInt(0).Rand(r, rs.P)
	X := new(bn256.G1).ScalarBaseMult(x)
	y := make([]*big.Int, rs.MaxSetLen)
	Y := make([]*bn256.G1, rs.MaxSetLen)
	_Y := make([]*bn256.G2, rs.MaxSetLen)
	Z := make(map[int]*bn256.G1)

	for i := 0; i < n; i++ {
		y = append(y, big.NewInt(0).Rand(r, rs.P))
		Y = append(Y, new(bn256.G1).ScalarBaseMult(y[i]))
		_Y = append(_Y, new(bn256.G2).ScalarBaseMult(y[i]))
	}
	for i := 0; i < n; i++ {
		for j := 0; j < i; j++ {
			t := big.NewInt(0).Mul(y[i], y[j])
			Z[(i+1)*n+j+1] = new(bn256.G1).ScalarBaseMult(t)
		}
	}

	return x, X, y, Y, _Y, Z
}

// Sign (sk, m)
func (rs *RS) Sign(x *big.Int, y []*big.Int, m []string) (*bn256.G1, *bn256.G1, *bn256.G2, *bn256.G2) {

	_r := rand.New(rand.NewSource(time.Now().UnixNano()))
	r := big.NewInt(0).Rand(_r, rs.P)
	sigma1 := new(bn256.G2).ScalarBaseMult(r)
	e := x
	for i := range y {
		hash := md5.New()
		mInt := big.NewInt(0).SetBytes(hash.Sum([]byte(m[i])))
		e.Add(e, mInt.Mul(mInt, y[i]))
	}
	sigma2 := new(bn256.G2).ScalarMult(sigma1, e)
	g11 := new(bn256.G1).ScalarBaseMult(big.NewInt(1))
	g12 := new(bn256.G1).ScalarBaseMult(big.NewInt(1))
	return g11, g12, sigma1, sigma2
}

// Verify (vkx, vky, m, sigma, r)
func (rs *RS) Verify(vk *bn256.G2, m string, sigma *bn256.G1) bool {
	// string message to big number
	msg := big.NewInt(0).SetBytes([]byte(m))

	t := new(bn256.G2)
	t.ScalarBaseMult(msg)
	t.Add(t, vk)
	g1 := new(bn256.G1).ScalarBaseMult(big.NewInt(1))
	g2 := new(bn256.G2).ScalarBaseMult(big.NewInt(1))
	left := bn256.Pair(sigma, t).String()
	right := bn256.Pair(g1, g2).String()
	return left == right
}

// func rsTest() {
// 	m := "abc123."
// 	p, _ := big.NewInt(0).SetString("1020831745583176952747469275099", 10)
// 	rs := new(RS)
// 	rs.Init(p)
// 	sk, vk := rs.Keygen(6)
// 	// println(sk, vk)
// 	sigma := rs.Sign(sk, m)
// 	// println(sigma)
// 	verify := rs.Verify(vk, m, sigma)
// 	println("RS test result: ", verify)
// }
