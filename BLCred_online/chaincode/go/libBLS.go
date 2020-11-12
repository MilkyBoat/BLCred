package main

import (
	"math/big"
	"math/rand"
	"time"

	"golang.org/x/crypto/bn256"
)

// BLS class
type BLS struct {
	P *big.Int
}

// Init (p)
func (bls *BLS) Init(_p *big.Int) {
	bls.P = _p
}

// Keygen ()
func (bls *BLS) Keygen() (*big.Int, *bn256.G2) {
	r := rand.New(rand.NewSource(time.Now().UnixNano()))
	x := big.NewInt(0).Rand(r, bls.P)
	X := new(bn256.G2).ScalarBaseMult(x)
	return x, X
}

// Sign (sk, m)
func (bls *BLS) Sign(x *big.Int, m string) *bn256.G1 {

	// string message to big number
	msg := big.NewInt(0).SetBytes([]byte(m))

	h := new(bn256.G1).ScalarBaseMult(msg)
	theta := new(bn256.G1).ScalarMult(h, x)

	return theta
}

// Verify (vk, m, sigma)
func (bls *BLS) Verify(X *bn256.G2, m string, sigma *bn256.G1) bool {

	// string message to big number
	msg := big.NewInt(0).SetBytes([]byte(m))
	h := new(bn256.G1).ScalarBaseMult(msg)

	// bn256.Pair has no "==" or euqle() function,
	// gt struct need to be serialized before determine whether equle
	g2 := new(bn256.G2).ScalarBaseMult(big.NewInt(1))
	left := bn256.Pair(sigma, g2).String()
	right := bn256.Pair(h, X).String()
	return left == right
}

func blsTest() {
	m := "abc123."
	p, _ := big.NewInt(0).SetString("1020831745583176952747469275099", 10)
	bls := new(BLS)
	bls.Init(p)
	sk, vk := bls.Keygen()
	// println(sk, vk)
	sigma := bls.Sign(sk, m)
	// println(sigma)
	verify := bls.Verify(vk, m, sigma)
	println("BLS test result: ", verify)
}
