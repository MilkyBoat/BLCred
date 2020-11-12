package main

import (
	"math/big"
	"math/rand"
	"time"

	"golang.org/x/crypto/bn256"
)

// BLS class
type BLS struct {
	Gg1 *bn256.G1
	Gg2 *bn256.G2
	P   *big.Int
	SK  *big.Int
	VK  *bn256.G2
	H   *bn256.G1
}

// Init (p)
func (bls *BLS) Init(_p *big.Int) {
	baseInt := big.NewInt(1)

	bls.Gg1 = new(bn256.G1).ScalarBaseMult(baseInt)
	bls.Gg2 = new(bn256.G2).ScalarBaseMult(baseInt)

	bls.SK = big.NewInt(0)
	bls.VK = new(bn256.G2)
	bls.P = _p
	bls.H = new(bn256.G1)
}

// Keygen ()
func (bls *BLS) Keygen() (*big.Int, *bn256.G2) {
	r := rand.New(rand.NewSource(time.Now().UnixNano()))
	bls.SK.Rand(r, bls.P)
	bls.VK = new(bn256.G2).ScalarBaseMult(bls.SK)
	return bls.SK, bls.VK
}

// Sign (sk, m)
func (bls *BLS) Sign(sk *big.Int, m string) *bn256.G1 {

	// string message to big number
	msg := big.NewInt(0).SetBytes([]byte(m))

	bls.H = new(bn256.G1).ScalarBaseMult(msg)
	theta := new(bn256.G1).ScalarMult(bls.H, bls.SK)

	return theta
}

// Verify (vk, m, theta)
func (bls *BLS) Verify(vk *bn256.G2, m string, theta *bn256.G1) bool {
	// bn256.Pair has no "==" or euqle() function, 
	// gt struct need to be serialized before determine whether equle
	return bn256.Pair(theta, bls.Gg2).String() == bn256.Pair(bls.H, bls.VK).String()
}

func blsTest() {
	m := "abc123."
	p, _ := big.NewInt(0).SetString("1020831745583176952747469275099", 10)
	bls := new(BLS)
	bls.Init(p)
	sk, vk := bls.Keygen()
	// println(sk, vk)
	theta := bls.Sign(sk, m)
	// println(theta)
	verify := bls.Verify(vk, m, theta)
	println(verify)
}
