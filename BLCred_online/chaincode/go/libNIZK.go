package main

import (
	"bytes"
	"crypto/md5"
	// "crypto/sha1"
	// "encoding/hex"
	// "io"
	"golang.org/x/crypto/bn256"
	"math/big"
	"math/rand"
	"time"
)

// NIZK class
type NIZK struct {
	P *big.Int
}

// NIZKPI pi param for NIZK
type NIZKPI struct {
	C *bn256.G1
	c *big.Int
	r []*big.Int
}

// Init (p)
func (nizk *NIZK) Init(_p *big.Int) {
	nizk.P = _p
}

func (nizk *NIZK) commitS(m []string, s *big.Int, P *bn256.G1, Q []*bn256.G1) *bn256.G1 {
	C := new(bn256.G1).ScalarMult(P, s)
	hash := md5.New()
	for i := range Q {
		msg := big.NewInt(0).SetBytes(hash.Sum([]byte(m[i])))
		C.Add(C, new(bn256.G1).ScalarMult(Q[i], msg))
	}
	return C
}

func (nizk *NIZK) revealS(C *bn256.G1, m []string, s *big.Int, P *bn256.G1, Q []*bn256.G1) bool {
	return nizk.commitS(m, s, P, Q).String() == C.String()
}

// ProveK (m, s, P, Q)
func (nizk *NIZK) ProveK(m []string, s *big.Int, P *bn256.G1, Q []*bn256.G1) NIZKPI {

	if len(m) != len(Q) {
		panic("message amount cann`t match Q")
	}

	C := nizk.commitS(m, s, P, Q)
	n := len(m)
	hash := md5.New()
	_r := rand.New(rand.NewSource(time.Now().UnixNano()))

	w := make([]*big.Int, n+1)
	for i := 0; i <= n; i++ {
		w[i] = big.NewInt(0).Rand(_r, bn256.Order)
	}

	W := new(bn256.G1).ScalarMult(P, w[n])
	for i := 0; i < n; i++ {
		W.Add(W, new(bn256.G1).ScalarMult(Q[i], w[i]))
	}

	buf := bytes.NewBuffer(P.Marshal())
	for _, v := range Q {
		buf.Write(v.Marshal())
	}
	buf.Write(C.Marshal())
	buf.Write(W.Marshal())
	c := big.NewInt(0).SetBytes(hash.Sum(buf.Bytes()))
	c.Mod(c, nizk.P)

	r := make([]*big.Int, n+1)
	for i := 0; i < n; i++ {
		msg := big.NewInt(0).SetBytes(hash.Sum([]byte(m[i])))
		// if i == 0 {
		// 	println(len(big.NewInt(0).Mul(msg, c).Bytes()))
		// }
		/* note that length of hash result shouldn`t bigger than half of len(bn256.Order)
		 * len(msg.Byte()) <= 16
		 * else the algorithm will get error result
		 */
		r[i] = big.NewInt(0).Sub(w[i], msg.Mul(msg, c))
	}
	r[n] = big.NewInt(0).Sub(w[n], big.NewInt(0).Mul(c, s))

	return NIZKPI{C, c, r}
}

// VerifyK (pi, P, Q)
func (nizk *NIZK) VerifyK(pi NIZKPI, P *bn256.G1, Q []*bn256.G1) bool {

	n := len(Q)
	hash := md5.New()

	W := new(bn256.G1).ScalarMult(pi.C, pi.c)
	W.Add(W, new(bn256.G1).ScalarMult(P, pi.r[n]))
	for i := 0; i < n; i++ {
		W.Add(W, new(bn256.G1).ScalarMult(Q[i], pi.r[i]))
	}

	buf := bytes.NewBuffer(P.Marshal())
	for _, v := range Q {
		buf.Write(v.Marshal())
	}
	buf.Write(pi.C.Marshal())
	buf.Write(W.Marshal())
	c := big.NewInt(0).SetBytes(hash.Sum(buf.Bytes()))
	c.Mod(c, nizk.P)

	return pi.c.String() == c.String()
}

// ProveDL (m, Q)
func (nizk *NIZK) ProveDL(m []string, Q []*bn256.G1) NIZKPI {

	if len(m) != len(Q) {
		panic("message amount cann`t match Q")
	}

	n := len(m)
	hash := md5.New()
	_r := rand.New(rand.NewSource(time.Now().UnixNano()))

	C := new(bn256.G1).ScalarBaseMult(big.NewInt(0))
	for i := 0; i < n; i++ {
		msg := big.NewInt(0).SetBytes(hash.Sum([]byte(m[i])))
		C.Add(C, new(bn256.G1).ScalarMult(Q[i], msg))
	}

	w := make([]*big.Int, n)
	for i := 0; i < n; i++ {
		w[i] = big.NewInt(0).Rand(_r, bn256.Order)
	}

	W := new(bn256.G1).ScalarBaseMult(big.NewInt(0))
	for i := 0; i < n; i++ {
		W.Add(W, new(bn256.G1).ScalarMult(Q[i], w[i]))
	}

	// to simplify the code, string here was Hash( C, Q[i], W ) which is diffrent from the paper
	buf := bytes.NewBuffer(C.Marshal())
	for _, v := range Q {
		buf.Write(v.Marshal())
	}
	buf.Write(W.Marshal())
	c := big.NewInt(0).SetBytes(hash.Sum(buf.Bytes()))
	c.Mod(c, nizk.P)

	r := make([]*big.Int, n)
	for i := 0; i < n; i++ {
		msg := big.NewInt(0).SetBytes(hash.Sum([]byte(m[i])))
		// if i == 0 {
		// 	println(len(big.NewInt(0).Mul(msg, c).Bytes()))
		// }
		r[i] = w[i].Sub(w[i], msg.Mul(msg, c))
	}

	return NIZKPI{C, c, r}
}

// VerifyDL (pi, Q)
func (nizk *NIZK) VerifyDL(pi NIZKPI, Q []*bn256.G1) bool {

	n := len(Q)
	hash := md5.New()

	t := new(bn256.G1).ScalarMult(pi.C, pi.c)
	for i := 0; i < n; i++ {
		t.Add(t, new(bn256.G1).ScalarMult(Q[i], pi.r[i]))
	}

	buf := bytes.NewBuffer(pi.C.Marshal())
	for _, v := range Q {
		buf.Write(v.Marshal())
	}
	buf.Write(t.Marshal())
	c := big.NewInt(0).SetBytes(hash.Sum(buf.Bytes()))
	c.Mod(c, nizk.P)

	return pi.c.String() == c.String()
}

func nizkTest() {
	p, _ := big.NewInt(0).SetString("18446744073709551557", 10)
	_r := rand.New(rand.NewSource(time.Now().UnixNano()))
	m := []string{"nezuko", "kawaii", "hhh", "lol2333"}
	s := big.NewInt(0).Rand(_r, p)
	P := new(bn256.G1).ScalarBaseMult(big.NewInt(0).Rand(_r, p))
	Q := make([]*bn256.G1, len(m))
	for i := range m {
		Q[i] = new(bn256.G1).ScalarBaseMult(big.NewInt(0).Rand(_r, p))
	}
	nizk := new(NIZK)
	nizk.Init(p)
	pi := nizk.ProveK(m, s, P, Q)
	verify1 := nizk.VerifyK(pi, P, Q)
	// 验证proveDL函数
	pi = nizk.ProveDL(m, Q)
	// 验证verifyDL函数
	verify2 := nizk.VerifyDL(pi, Q)
	println("NIZK test result: ", verify1, " ", verify2)
}
