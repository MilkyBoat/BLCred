package main

import (
	"math/big"
	"math/rand"
	"time"

	"golang.org/x/crypto/bn256"
)

// FBB class
type FBB struct {
	Gg1 *bn256.G1
	Gg2 *bn256.G2
	P   *big.Int
	SK  *big.Int
	VK  *bn256.G2
	H   *bn256.G1
}

// Init (p)
func (fbb *FBB) Init(_p *big.Int) {
	baseInt := big.NewInt(1)

	fbb.Gg1 = new(bn256.G1).ScalarBaseMult(baseInt)
	fbb.Gg2 = new(bn256.G2).ScalarBaseMult(baseInt)

	fbb.SK = big.NewInt(0)
	fbb.VK = new(bn256.G2)
	fbb.P = _p
	fbb.H = new(bn256.G1)
}

// Keygen ()
func (fbb *FBB) Keygen() (*big.Int, *bn256.G2) {
	r := rand.New(rand.NewSource(time.Now().UnixNano()))
	fbb.SK.Rand(r, fbb.P)
	fbb.VK = new(bn256.G2).ScalarBaseMult(fbb.SK)
	return fbb.SK, fbb.VK
}

// Sign (sk, m)
func (fbb *FBB) Sign(sk *big.Int, m string) *bn256.G1 {

	// string message to big number
	msg := big.NewInt(0).SetBytes([]byte(m))

	fbb.H = new(bn256.G1).ScalarBaseMult(msg)
	theta := new(bn256.G1).ScalarMult(fbb.H, fbb.SK)

	return theta
}

// Verify (vk, m, theta)
func (fbb *FBB) Verify(vk *bn256.G2, m string, theta *bn256.G1) bool {
	// bn256.Pair has no "==" or euqle() function,
	// gt struct need to be serialized before determine whether equle
	return bn256.Pair(theta, fbb.Gg2).String() == bn256.Pair(fbb.H, fbb.VK).String()
}

func fbbTest() {
	m := "abc123."
	p, _ := big.NewInt(0).SetString("1020831745583176952747469275099", 10)
	fbb := new(FBB)
	fbb.Init(p)
	sk, vk := fbb.Keygen()
	// println(sk, vk)
	theta := fbb.Sign(sk, m)
	// println(theta)
	verify := fbb.Verify(vk, m, theta)
	println(verify)
}
