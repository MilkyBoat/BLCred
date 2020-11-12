package main

import (
	"math/big"
	"math/rand"
	"time"

	"golang.org/x/crypto/bn256"
)

// WBB class
type WBB struct {
	P *big.Int
}

// Init (p)
func (wbb *WBB) Init(_p *big.Int) {
	wbb.P = _p
}

// Keygen ()
func (wbb *WBB) Keygen() (*big.Int, *bn256.G2) {

	r := rand.New(rand.NewSource(0))
	r.Seed(time.Now().UnixNano())
	x := big.NewInt(0).Rand(r, wbb.P)
	X := new(bn256.G2).ScalarBaseMult(x)

	return x, X
}

// Sign (sk, m)
func (wbb *WBB) Sign(sk *big.Int, m string) *bn256.G1 {

	// string message to big number
	msg := big.NewInt(0).SetBytes([]byte(m))

	if big.NewInt(0).Add(sk, msg) == big.NewInt(0) {
		panic("This sk can`t be used to encrypt current message, please rerun kegen function")
		return nil
	}

	exp := big.NewInt(0).ModInverse(msg.Add(msg, sk), bn256.Order)
	sigma := new(bn256.G1).ScalarBaseMult(exp)
	return sigma
}

// Verify (vkx, vky, m, sigma, r)
func (wbb *WBB) Verify(vk *bn256.G2, m string, sigma *bn256.G1) bool {
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

func wbbTest() {
	m := "abc123."
	p, _ := big.NewInt(0).SetString("1020831745583176952747469275099", 10)
	wbb := new(WBB)
	wbb.Init(p)
	sk, vk := wbb.Keygen()
	// println(sk, vk)
	sigma := wbb.Sign(sk, m)
	// println(sigma)
	verify := wbb.Verify(vk, m, sigma)
	println("WBB test result: ", verify)
}
