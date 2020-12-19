package main

import (
	"crypto/md5"
	// "golang.org/x/crypto/bn256"
	"github.com/drbh/zkproofs/go-ethereum/crypto/bn256"
	"math/big"
	"math/rand"
	"time"
)

// FBB class
type FBB struct {
	P *big.Int
}

// Init (p)
func (fbb *FBB) Init(_p *big.Int) {
	fbb.P = _p
}

// Keygen ()
func (fbb *FBB) Keygen() (*big.Int, *big.Int, *bn256.G2, *bn256.G2) {

	r := rand.New(rand.NewSource(0))
	r.Seed(time.Now().UnixNano())
	x := big.NewInt(0).Rand(r, fbb.P)
	X := new(bn256.G2).ScalarBaseMult(x)
	r.Seed(time.Now().UnixNano())
	y := big.NewInt(0).Rand(r, fbb.P)
	Y := new(bn256.G2).ScalarBaseMult(y)

	return x, y, X, Y
}

// Sign (sk, m)
func (fbb *FBB) Sign(skx *big.Int, sky *big.Int, m string) (*bn256.G1, *big.Int) {

	// string message to big number
	hash := md5.New()
	msg := big.NewInt(0).SetBytes(hash.Sum([]byte(m)))

	_r := rand.New(rand.NewSource(time.Now().UnixNano()))
	t1 := big.NewInt(0)
	t2 := big.NewInt(0)
	r := big.NewInt(0).Rand(_r, fbb.P)
	for t1.Add(t1.Add(skx, t2.Mul(r, sky)), msg) == big.NewInt(0) {
		_r.Seed(time.Now().UnixNano())
		r.Rand(_r, fbb.P)
	}
	t3 := big.NewInt(0).ModInverse(t1, bn256.Order)
	sigma := new(bn256.G1).ScalarBaseMult(t3)

	return sigma, r
}

// Verify (vkx, vky, m, sigma, r)
func (fbb *FBB) Verify(vkx *bn256.G2, vky *bn256.G2, m string, sigma *bn256.G1, r *big.Int) bool {
	// string message to big number
	hash := md5.New()
	msg := big.NewInt(0).SetBytes(hash.Sum([]byte(m)))

	t := new(bn256.G2)
	t.ScalarMult(vky, r)
	t.Add(vkx, t)
	t.Add(t, new(bn256.G2).ScalarBaseMult(msg))
	g1 := new(bn256.G1).ScalarBaseMult(big.NewInt(1))
	g2 := new(bn256.G2).ScalarBaseMult(big.NewInt(1))
	left := bn256.Pair(sigma, t).String()
	right := bn256.Pair(g1, g2).String()
	return left == right
}

func fbbTest() {
	m := "abc123."
	p, _ := big.NewInt(0).SetString("1020831745583176952747469275099", 10)
	fbb := new(FBB)
	fbb.Init(p)
	skx, sky, vkx, vky := fbb.Keygen()
	// println(sk, vk)
	sigma, r := fbb.Sign(skx, sky, m)
	// println(sigma)
	verify := fbb.Verify(vkx, vky, m, sigma, r)
	println("FBB test result: ", verify)
}
