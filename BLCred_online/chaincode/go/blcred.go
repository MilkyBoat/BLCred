package main

import (
	"bytes"
	"encoding/binary"
	"fmt"
	// "golang.org/x/crypto/bn256"
	"github.com/drbh/zkproofs/go-ethereum/crypto/bn256"
	"math/big"
	"math/rand"
	"strconv"
	"time"

	// "github.com/hyperledger/fabric/core/chaincode/shim"
	// sc "github.com/hyperledger/fabric/protos/peer"
	"github.com/hyperledger/fabric-chaincode-go/shim"
	sc "github.com/hyperledger/fabric-protos-go/peer"
)

// SmartContract :
type SmartContract struct {
	P *big.Int
}

// SigmaShow :
type SigmaShow struct {
	sigma bn256.G1
	r     big.Int
	X     bn256.G2
	Y     bn256.G2
	pi    NIZKPI
}

func (s *SigmaShow) bytes() []byte {
	buf := bytes.NewBuffer([]byte{})
	binary.Write(buf, binary.BigEndian, s.sigma.Marshal())    // 64 bytes
	binary.Write(buf, binary.BigEndian, s.r.Bytes())          // 8 bytes
	binary.Write(buf, binary.BigEndian, s.X.Marshal())        // 128 bytes
	binary.Write(buf, binary.BigEndian, s.Y.Marshal())        // 128 bytes
	binary.Write(buf, binary.BigEndian, s.pi.NIZKC.Marshal()) // 128 bytes
	binary.Write(buf, binary.BigEndian, s.pi.NIZKc.Bytes())   // 8 bytes
	for _, v := range s.pi.NIZKr {
		binary.Write(buf, binary.BigEndian, []byte(v.Bytes())) // 32*n bytes
	}
	return buf.Bytes()
}

func (s *SigmaShow) fromBytes(buf []byte) bool {
	if len(buf) < 528 || (len(buf)-464)%32 != 0 {
		return false
	}
	psigma, _ := new(bn256.G1).Unmarshal(buf[:64])
	s.sigma = *psigma
	s.r = *big.NewInt(0).SetBytes(buf[64:72])
	pX, _ := new(bn256.G2).Unmarshal(buf[72:200])
	s.X = *pX
	pY, _ := new(bn256.G2).Unmarshal(buf[200:328])
	s.Y = *pY
	s.pi = *new(NIZKPI)
	s.pi.NIZKC, _ = new(bn256.G2).Unmarshal(buf[328:456])
	s.pi.NIZKc = big.NewInt(0).SetBytes(buf[456:464])
	n := (len(buf) - 464) / 32
	s.pi.NIZKr = make([]*big.Int, n)
	for i := 0; i < n; i++ {
		s.pi.NIZKr[i] = big.NewInt(0).SetBytes(buf[464+i*32 : 464+(i+1)*32])
	}
	return true
}

// Init :
func (s *SmartContract) Init(APIstub shim.ChaincodeStubInterface) sc.Response {
	return shim.Success(nil)
}

// Invoke :
func (s *SmartContract) Invoke(APIstub shim.ChaincodeStubInterface) sc.Response {

	function, args := APIstub.GetFunctionAndParameters()

	if function == "setup" {
		return s.setup(APIstub)
	} else if function == "authkeygen" {
		return s.authkeygen(APIstub, args)
	} else if function == "ukeygen" {
		return s.ukeygen(APIstub)
	} else if function == "issuecred" {
		return s.issuecred(APIstub, args)
	} else if function == "deriveshow" {
		return s.deriveshow(APIstub, args)
	} else if function == "credverify" {
		return s.credverify(APIstub, args)
	}

	return shim.Error("Invalid Smart Contract function name.")
}

// setup()
func (s *SmartContract) setup(APIstub shim.ChaincodeStubInterface) sc.Response {
	P, _ := big.NewInt(0).SetString("18446744073709551557", 10)
	APIstub.PutState("BLCred_P", P.Bytes())
	// do nothing if use NIZK schnor
	return shim.Success(nil)
}

// authkeygen(n)
func (s *SmartContract) authkeygen(APIstub shim.ChaincodeStubInterface, args []string) sc.Response {

	if len(args) != 1 {
		return shim.Error("Incorrect number of arguments. Expecting 1")
	}

	PBytes, _ := APIstub.GetState("BLCred_P")
	BLCredP := big.NewInt(0).SetBytes(PBytes)

	rs := new(RS)
	rs.Init(BLCredP)
	n, _ := strconv.Atoi(args[0])
	rssk, rsvk := rs.Keygen(n)

	APIstub.PutState("avk", rsvk.Bytes())

	buf := bytes.NewBuffer([]byte{})
	binary.Write(buf, binary.BigEndian, rssk.Bytes())

	return shim.Success(buf.Bytes())
}

// ukeygen()
func (s *SmartContract) ukeygen(APIstub shim.ChaincodeStubInterface) sc.Response {

	PBytes, _ := APIstub.GetState("BLCred_P")
	BLCredP := big.NewInt(0).SetBytes(PBytes)

	bls := new(BLS)
	bls.Init(BLCredP)
	sk, vk := bls.Keygen()

	// encode sk and vk to []byte
	APIstub.PutState("uvk", vk.Marshal())
	bsk := sk.String()

	return shim.Success([]byte(bsk))
}

// issuecred(m1,m2 ...)
/*
 * Technically, in this function, the code executed by the user and the
 * code executed by the Authenticator should be divided into two functions,
 * which will be called by user and authenticator respectively. Because
 * this function needs to receive respective private key as parameter.
 * In this project, we want to simplified the code and we merged them into
 * one function. This will not significantly affect the results or performance.
 */
func (s *SmartContract) issuecred(APIstub shim.ChaincodeStubInterface, args []string) sc.Response {

	if len(args) <= 1 {
		return shim.Error("Incorrect number of arguments. Expecting at least 1")
	}

	PBytes, _ := APIstub.GetState("BLCred_P")
	BLCredP := big.NewInt(0).SetBytes(PBytes)
	r := rand.New(rand.NewSource(time.Now().UnixNano()))
	uvkb, _ := APIstub.GetState("uvk")
	uvk, _ := new(bn256.G2).Unmarshal(uvkb)
	avkb, _ := APIstub.GetState("avk")
	avk := new(RSVK)
	if !avk.FromBytes(avkb, 64, 128, 4) {
		return shim.Error("Decode avk failure.")
	}

	// user part:
	nizk := new(NIZK)
	nizk.Init(BLCredP)
	S := big.NewInt(0).Rand(r, BLCredP)
	P := uvk
	Q := []*bn256.G2{}
	for i := 0; i < len(args); i++ {
		qi := big.NewInt(0).Rand(r, BLCredP)
		Qi := new(bn256.G2).ScalarBaseMult(qi)
		Q = append(Q, Qi)
	}
	pik := nizk.ProveK(args, S, P, Q)
	pidl := nizk.ProveDL(args, Q)

	// auth part:
	sigmaCred0 := new(bn256.G2)
	sigmaCred1 := new(bn256.G2)
	if nizk.VerifyK(pik, P, Q) && nizk.VerifyDL(pidl, Q) {
		w := big.NewInt(0).Rand(r, BLCredP)
		sigmaCred0.ScalarMult(uvk, w)
		sigmaCred1.Add(avk.VK_X, pik.NIZKC)
		sigmaCred1.ScalarMult(sigmaCred1, w)
	} else {
		panic("Auth check failed!")
	}
	sigmaCred1.ScalarMult(sigmaCred1, S)
	temp := new(bn256.G2).Neg(sigmaCred1)
	sigmaCred1.Add(sigmaCred0, temp)

	sigmaCred := SIGMA{
		new(bn256.G1).ScalarBaseMult(big.NewInt(1)),
		new(bn256.G1).ScalarBaseMult(big.NewInt(1)),
		sigmaCred0,
		sigmaCred1,
	}

	sigmaCredb := sigmaCred.Bytes()
	APIstub.PutState("sigmaCred", sigmaCredb)

	return shim.Success(sigmaCredb)
}

// deriveshow(phi,usk,D,m...)
func (s *SmartContract) deriveshow(APIstub shim.ChaincodeStubInterface, args []string) sc.Response {

	if len(args) < 4 {
		return shim.Error("Incorrect number of arguments. Expecting at least 4")
	}

	PBytes, _ := APIstub.GetState("BLCred_P")
	BLCredP := big.NewInt(0).SetBytes(PBytes)
	_rand := rand.New(rand.NewSource(time.Now().UnixNano()))
	usk, _ := big.NewInt(0).SetString(args[1], 10)
	uvkb, _ := APIstub.GetState("uvk")
	avkb, _ := APIstub.GetState("avk")
	avk := new(RSVK)
	if !avk.FromBytes(avkb, 64, 128, 4) {
		return shim.Error("Decode avk failure.")
	}
	sigmaCred := new(SIGMA)
	sigmaCredb, _ := APIstub.GetState("sigmaCred")
	if !sigmaCred.FromBytes(sigmaCredb) {
		return shim.Error("Decode sigmaCred failure.")
	}

	fbb := new(FBB)
	fbb.Init(BLCredP)
	fbbx, fbby, fbbX, fbbY := fbb.Keygen()
	ptH := string(append(fbbX.Marshal(), fbbY.Marshal()...))

	bls := new(BLS)
	bls.Init(BLCredP)
	sigmas := bls.Sign(usk, ptH)

	rs := new(RS)
	rs.Init(BLCredP)
	sigmad := rs.Derive(*avk, *sigmaCred, String2D(args[2]), args[3:])

	nizk := new(NIZK)
	nizk.Init(BLCredP)
	mbuf := bytes.NewBuffer([]byte{})
	for _, v := range args[3:] {
		binary.Write(mbuf, binary.BigEndian, v)
	}
	binary.Write(mbuf, binary.BigEndian, uvkb)
	binary.Write(mbuf, binary.BigEndian, sigmas.Marshal())
	binary.Write(mbuf, binary.BigEndian, sigmad.Bytes())
	mi := make([]string, 1)
	mi[0] = string(mbuf.Bytes())
	S := big.NewInt(0).Rand(_rand, BLCredP)
	P := new(bn256.G2).ScalarBaseMult(big.NewInt(0).Rand(_rand, BLCredP))
	Q := make([]*bn256.G2, 1)
	Q[0] = new(bn256.G2).ScalarBaseMult(big.NewInt(0).Rand(_rand, BLCredP))
	piNIZK := nizk.ProveK(mi, S, P, Q)
	APIstub.PutState("P", P.Marshal())
	APIstub.PutState("Q", Q[0].Marshal())

	buf := bytes.NewBuffer([]byte{})
	binary.Write(buf, binary.BigEndian, piNIZK.NIZKC.Marshal()) // 128 bytes
	binary.Write(buf, binary.BigEndian, piNIZK.NIZKc.Bytes())   // 8 bytes
	for _, v := range piNIZK.NIZKr {
		binary.Write(buf, binary.BigEndian, []byte(v.Bytes())) // 8*n bytes
	}
	m := string(buf.Bytes()) + string(args[0]) + ptH
	sig, r := fbb.Sign(fbbx, fbby, m)
	sigmaShow := SigmaShow{*sig, *r, *fbbX, *fbbY, piNIZK}

	sigmaShowb := sigmaShow.bytes()
	APIstub.PutState("sigmaShow", sigmaShowb)

	return shim.Success(sigmaShowb)
}

// credverify(phi)
func (s *SmartContract) credverify(APIstub shim.ChaincodeStubInterface, args []string) sc.Response {

	if len(args) != 1 {
		return shim.Error("Incorrect number of arguments. Expecting 1")
	}

	PBytes, _ := APIstub.GetState("BLCred_P")
	BLCredP := big.NewInt(0).SetBytes(PBytes)

	var sigmaShow SigmaShow
	sigmaShowb, _ := APIstub.GetState("sigmaShow")
	if !sigmaShow.fromBytes(sigmaShowb) {
		return shim.Error("Decode sigmaShow failure.")
	}
	piNIZK := sigmaShow.pi

	nizk := new(NIZK)
	nizk.Init(BLCredP)
	Pb, _ := APIstub.GetState("P")
	P, _ := new(bn256.G2).Unmarshal(Pb)
	Q0b, _ := APIstub.GetState("Q")
	Q := make([]*bn256.G2, 1)
	Q[0], _ = new(bn256.G2).Unmarshal(Q0b)
	result1 := nizk.VerifyK(piNIZK, P, Q)

	buf := bytes.NewBuffer([]byte{})
	binary.Write(buf, binary.BigEndian, piNIZK.NIZKC.Marshal()) // 128 bytes
	binary.Write(buf, binary.BigEndian, piNIZK.NIZKc.Bytes())   // 8 bytes
	for _, v := range piNIZK.NIZKr {
		binary.Write(buf, binary.BigEndian, []byte(v.Bytes())) // 32*n bytes
	}
	otsvk := string(append(sigmaShow.X.Marshal(), sigmaShow.Y.Marshal()...))
	m := string(buf.Bytes()) + string(args[0]) + otsvk

	fbb := new(FBB)
	fbb.Init(BLCredP)
	result2 := fbb.Verify(&sigmaShow.X, &sigmaShow.Y, m, &sigmaShow.sigma, &sigmaShow.r)
	if result1 && result2 {
		return shim.Success([]byte("1"))
	}
	return shim.Success([]byte("0"))
}

func main() {

	test := false

	if test {
		blsTest()
		fbbTest()
		wbbTest()
		rsTest()
		nizkTest()
		return
	}

	err := shim.Start(new(SmartContract))
	if err != nil {
		fmt.Printf("Error creating new Smart Contract: %s", err)
	}

}
