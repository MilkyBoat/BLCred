package main

import (
	"bytes"
	"crypto/md5"
	"encoding/binary"
	"fmt"

	// "golang.org/x/crypto/bn256"
	"math/big"
	"math/rand"
	"strconv"
	"time"

	"github.com/drbh/zkproofs/go-ethereum/crypto/bn256"

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
	LK big.Int
	pi NIZKPI
}

func (s *SigmaShow) bytes() []byte {
	buf := bytes.NewBuffer([]byte{})
	binary.Write(buf, binary.BigEndian, s.LK.Bytes())         // 8 bytes
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
	s.LK = *big.NewInt(0).SetBytes(buf[64:72])
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
	payload := []byte("")
	start := time.Now()

	if function == "setup" {
		payload = s.setup(APIstub)
	} else if function == "ipkeygen" {
		payload = s.ipkeygen(APIstub, args)
	} else if function == "ukeygen" {
		payload = s.ukeygen(APIstub)
	} else if function == "skeygen" {
		payload = s.skeygen(APIstub)
	} else if function == "issuecred" {
		payload = s.issuecred(APIstub, args)
	} else if function == "deriveshow" {
		payload = s.deriveshow(APIstub, args)
	} else if function == "link" {
		if s.link(APIstub, args) {
			payload = []byte("1")
		} else {
			payload = []byte("0")
		}
	} else {
		return shim.Error("Invalid Smart Contract function name.")
	}

	result := fmt.Sprintf("%s|%s", time.Since(start), payload)

	return shim.Success([]byte(result))
}

// setup()
func (s *SmartContract) setup(APIstub shim.ChaincodeStubInterface) []byte {
	P, _ := big.NewInt(0).SetString("18446744073709551557", 10)
	APIstub.PutState("BLCred_P", P.Bytes())
	// do nothing if use NIZK schnor
	return nil
}

// ipkeygen(n)
func (s *SmartContract) ipkeygen(APIstub shim.ChaincodeStubInterface, args []string) []byte {

	if len(args) != 1 {
		return []byte("Incorrect number of arguments. Expecting 1")
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

	return buf.Bytes()
}

// ukeygen()
func (s *SmartContract) ukeygen(APIstub shim.ChaincodeStubInterface) []byte {

	PBytes, _ := APIstub.GetState("BLCred_P")
	BLCredP := big.NewInt(0).SetBytes(PBytes)

	bls := new(BLS)
	bls.Init(BLCredP)
	sk, vk := bls.Keygen()

	// encode sk and vk to []byte
	APIstub.PutState("uvk", vk.Marshal())
	bsk := sk.String()

	return []byte(bsk)
}

// skeygen()
func (s *SmartContract) skeygen(APIstub shim.ChaincodeStubInterface) []byte {

	PBytes, _ := APIstub.GetState("BLCred_P")
	BLCredP := big.NewInt(0).SetBytes(PBytes)

	bls := new(BLS)
	bls.Init(BLCredP)
	sk, vk := bls.Keygen()

	// encode sk and vk to []byte
	APIstub.PutState("svk", vk.Marshal())
	bsk := sk.String()

	return []byte(bsk)
}

// [inner function]commit : (user)
func (s *SmartContract) commit(BLCredP *big.Int, uvk *bn256.G2, avk *RSVK, m []string) (
	*bn256.G2, *big.Int, NIZKPI, NIZKPI, []*bn256.G2) {
	nizk := new(NIZK)
	nizk.Init(BLCredP)
	hash := md5.New()
	r := rand.New(rand.NewSource(time.Now().UnixNano()))

	S := big.NewInt(0).Rand(r, BLCredP)
	C := new(bn256.G2).ScalarMult(uvk, S)
	P := uvk
	Q := []*bn256.G2{}
	for i := 0; i < len(m); i++ {
		msg := big.NewInt(0).SetBytes(hash.Sum([]byte(m[i])))
		C.Add(C, new(bn256.G2).ScalarMult(avk.VK_Y[i], msg))

		qi := big.NewInt(0).Rand(r, BLCredP)
		Qi := new(bn256.G2).ScalarBaseMult(qi)
		Q = append(Q, Qi)
	}
	pik := nizk.ProveK(m, S, P, Q)
	pidl := nizk.ProveDL(m, Q)
	return C, S, pik, pidl, Q
}

// [inner function]issue : (auth)
func (s *SmartContract) issue(BLCredP *big.Int, pik NIZKPI, pidl NIZKPI, Q []*bn256.G2, avk *RSVK, C *bn256.G2, uvk *bn256.G2) SIGMA {
	nizk := new(NIZK)
	nizk.Init(BLCredP)
	sigmaCred1 := new(bn256.G2)
	sigmaCred2 := new(bn256.G2)
	r := rand.New(rand.NewSource(time.Now().UnixNano()))
	w := big.NewInt(0).Rand(r, BLCredP)
	if nizk.VerifyK(pik, uvk, Q) && nizk.VerifyDL(pidl, Q) {
		sigmaCred1.ScalarMult(uvk, w)
		sigmaCred2.Add(avk.VK_X, C)
		sigmaCred2.ScalarMult(sigmaCred2, w)
	} else {
		panic("Auth check failed!")
	}

	sigmaCred := SIGMA{
		new(bn256.G1).ScalarBaseMult(big.NewInt(1)),
		new(bn256.G1).ScalarBaseMult(big.NewInt(1)),
		sigmaCred1,
		sigmaCred2,
	}
	return sigmaCred
}

// [inner function]unblind : (user)
func (s *SmartContract) unblind(sigmaCred SIGMA, S *big.Int) SIGMA {
	temp := new(bn256.G2).ScalarMult(sigmaCred.sigma21, S)
	temp.Neg(temp)
	sigmaCred.sigma21.Add(sigmaCred.sigma21, temp)
	return sigmaCred
}

// issuecred(m1,m2 ...)
/*
 * Technically, in this function, the code executed by the user and the
 * code executed by the Authenticator should be divided into two functions,
 * which will be called by user and authenticator respectively. Because
 * this function needs to receive respective private key as parameter.
 * In this project, we want to simplified the code and we merged them into
 * one function. This will not significantly affect the performance results.
 */
func (s *SmartContract) issuecred(APIstub shim.ChaincodeStubInterface, args []string) []byte {

	if len(args) < 1 {
		return []byte("Incorrect number of arguments. Expecting at least 1")
	}

	PBytes, _ := APIstub.GetState("BLCred_P")
	BLCredP := big.NewInt(0).SetBytes(PBytes)
	uvkb, _ := APIstub.GetState("uvk")
	uvk, _ := new(bn256.G2).Unmarshal(uvkb)
	// svkb, _ := APIstub.GetState("svk")
	// svk, _ := new(bn256.G2).Unmarshal(svkb)
	avkb, _ := APIstub.GetState("avk")
	avk := new(RSVK)
	if !avk.FromBytes(avkb, 64, 128, 4) {
		return []byte("Decode avk failure.")
	}

	// user part:
	C, S, pik, pidl, Q := s.commit(BLCredP, uvk, avk, args)

	// auth part:
	sigmaCred := s.issue(BLCredP, pik, pidl, Q, avk, C, uvk)

	// user part
	sigmaCred = s.unblind(sigmaCred, S)

	sigmaCredb := sigmaCred.Bytes()
	APIstub.PutState("sigmaCred", sigmaCredb)

	return sigmaCredb
}

// deriveshow(phi,usk,D,m...)
func (s *SmartContract) deriveshow(APIstub shim.ChaincodeStubInterface, args []string) []byte {

	if len(args) < 3 {
		return []byte("Incorrect number of arguments. Expecting at least 4")
	}

	PBytes, _ := APIstub.GetState("BLCred_P")
	BLCredP := big.NewInt(0).SetBytes(PBytes)
	_rand := rand.New(rand.NewSource(time.Now().UnixNano()))
	usk, _ := big.NewInt(0).SetString(args[0], 10)
	uvkb, _ := APIstub.GetState("uvk")
	uvk, _ := new(bn256.G2).Unmarshal(uvkb)
	avkb, _ := APIstub.GetState("avk")
	avk := new(RSVK)
	if !avk.FromBytes(avkb, 64, 128, 4) {
		return []byte("Decode avk failure.")
	}
	sigmaCred := new(SIGMA)
	sigmaCredb, _ := APIstub.GetState("sigmaCred")
	if !sigmaCred.FromBytes(sigmaCredb) {
		return []byte("Decode sigmaCred failure.")
	}

	rs := new(RS)
	rs.Init(BLCredP)
	sigmad := rs.Derive(*avk, *sigmaCred, String2D(args[1]), args[2:])

	tag := big.NewInt(0).Rand(_rand, BLCredP)
	hash := md5.New()
	LK := big.NewInt(0).SetBytes(hash.Sum(append(tag.Bytes(), usk.Bytes()...)))

	nizk := new(NIZK)
	nizk.Init(BLCredP)
	mbuf := bytes.NewBuffer([]byte{})
	for _, v := range args[2:] {
		binary.Write(mbuf, binary.BigEndian, []byte(v))
	}
	binary.Write(mbuf, binary.BigEndian, uvkb)
	binary.Write(mbuf, binary.BigEndian, sigmad.Bytes())
	mi := make([]string, 1)
	mi[0] = mbuf.String()
	S := big.NewInt(0).Rand(_rand, BLCredP)
	P := uvk
	Q := make([]*bn256.G2, 1)
	Q[0] = new(bn256.G2).ScalarBaseMult(big.NewInt(0).Rand(_rand, BLCredP))
	piNIZK := nizk.ProveK(mi, S, P, Q)
	APIstub.PutState("Q", Q[0].Marshal())

	sigmaShow := SigmaShow{*LK, piNIZK}

	sigmaShowb := sigmaShow.bytes()
	APIstub.PutState("sigmaShow", sigmaShowb)

	return sigmaShowb
}

// link(sigmashow1, sigmashow2) (encode with base64)
func (s *SmartContract) link(APIstub shim.ChaincodeStubInterface, args []string) bool {
	return args[0] == args[1]
}

// credverify(phi)
// func (s *SmartContract) credverify(APIstub shim.ChaincodeStubInterface, args []string) []byte {

// 	if len(args) != 1 {
// 		return []byte("Incorrect number of arguments. Expecting 1")
// 	}

// 	PBytes, _ := APIstub.GetState("BLCred_P")
// 	BLCredP := big.NewInt(0).SetBytes(PBytes)

// 	var sigmaShow SigmaShow
// 	sigmaShowb, _ := APIstub.GetState("sigmaShow")
// 	if !sigmaShow.fromBytes(sigmaShowb) {
// 		return []byte("Decode sigmaShow failure.")
// 	}
// 	piNIZK := sigmaShow.pi

// 	nizk := new(NIZK)
// 	nizk.Init(BLCredP)
// 	Pb, _ := APIstub.GetState("P")
// 	P, _ := new(bn256.G2).Unmarshal(Pb)
// 	Q0b, _ := APIstub.GetState("Q")
// 	Q := make([]*bn256.G2, 1)
// 	Q[0], _ = new(bn256.G2).Unmarshal(Q0b)
// 	result1 := nizk.VerifyK(piNIZK, P, Q)

// 	buf := bytes.NewBuffer([]byte{})
// 	binary.Write(buf, binary.BigEndian, piNIZK.NIZKC.Marshal()) // 128 bytes
// 	binary.Write(buf, binary.BigEndian, piNIZK.NIZKc.Bytes())   // 8 bytes
// 	for _, v := range piNIZK.NIZKr {
// 		binary.Write(buf, binary.BigEndian, []byte(v.Bytes())) // 32*n bytes
// 	}
// 	otsvk := string(append(sigmaShow.X.Marshal(), sigmaShow.Y.Marshal()...))
// 	m := string(buf.Bytes()) + string(args[0]) + otsvk

// 	fbb := new(FBB)
// 	fbb.Init(BLCredP)
// 	result2 := fbb.Verify(&sigmaShow.X, &sigmaShow.Y, m, &sigmaShow.sigma, &sigmaShow.r)
// 	if result1 && result2 {
// 		return []byte("1")
// 	}
// 	return []byte("0")
// }

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
