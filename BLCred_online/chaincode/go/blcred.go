package main

import (
	"bytes"
	"encoding/binary"
	"encoding/json"
	"fmt"
	"golang.org/x/crypto/bn256"
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
	m     string
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

	buf := bytes.NewBuffer([]byte{})
	jsonRssk, _ := json.Marshal(&rssk)
	// binary.Write(buf, binary.BigEndian, len(bsk))
	binary.Write(buf, binary.BigEndian, jsonRssk)
	jsonRsvk, _ := json.Marshal(&rsvk)
	// binary.Write(buf, binary.BigEndian, len(bvk))
	binary.Write(buf, binary.BigEndian, jsonRsvk)

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
	bsk := sk.Bytes()
	bvk := vk.Marshal()
	buf := bytes.NewBuffer([]byte{})
	// binary.Write(buf, binary.BigEndian, len(bsk))
	binary.Write(buf, binary.BigEndian, bsk)
	// binary.Write(buf, binary.BigEndian, len(bvk))
	binary.Write(buf, binary.BigEndian, bvk)

	return shim.Success(buf.Bytes())
}

// issuecred(usk,uvk,avk,m1,m2 ...)
/*
 * Technically, in this function, the code executed by the user and the
 * code executed by the Authenticator should be divided into two functions,
 * which will be called by user and Authenticator respectively. Because
 * this function needs to receive respective private key as parameter.
 * In this project, we want to simplified the code and we merged them into
 * one function. This will not affect the results or performance.
 */
func (s *SmartContract) issuecred(APIstub shim.ChaincodeStubInterface, args []string) sc.Response {

	if len(args) <= 3 {
		return shim.Error("Incorrect number of arguments. Expecting 3")
	}

	PBytes, _ := APIstub.GetState("BLCred_P")
	BLCredP := big.NewInt(0).SetBytes(PBytes)
	r := rand.New(rand.NewSource(time.Now().UnixNano()))
	uvk, _ := new(bn256.G2).Unmarshal([]byte(args[1]))
	var avk RSVK
	json.Unmarshal([]byte(args[2]), &avk)

	// user part:
	nizk := new(NIZK)
	nizk.Init(BLCredP)
	S := big.NewInt(0).Rand(r, BLCredP)
	P := uvk
	Q := []*bn256.G2{}
	for i := 0; i < len(args)-3; i++ {
		qi := big.NewInt(0).Rand(r, BLCredP)
		Qi := new(bn256.G2).ScalarBaseMult(qi)
		Q = append(Q, Qi)
	}
	pik := nizk.ProveK(args[2:], S, P, Q)
	pidl := nizk.ProveDL(args[0:1], Q)

	// auth part:
	sigmaCred0 := new(bn256.G2)
	sigmaCred1 := new(bn256.G2)
	if nizk.VerifyK(pik, P, Q) && nizk.VerifyDL(pidl, Q) {
		w := big.NewInt(0).Rand(r, BLCredP)
		sigmaCred0 = sigmaCred0.ScalarMult(uvk, w)
		sigmaCred1 = sigmaCred1.Add(avk._X, pik.C)
		sigmaCred1 = sigmaCred1.ScalarMult(sigmaCred1, w)
	} else {
		panic("Auth check failed!")
	}
	sigmaCred1 = sigmaCred1.ScalarMult(sigmaCred1, S)
	// FIXIT: golang bn256.G2 struct has no Neg function
	// sigmaCred1 = sigmaCred1.Neg(sigmaCred1)
	sigmaCred1 = sigmaCred1.Add(sigmaCred0, sigmaCred1)

	sigmaCred := SIGMA{
		new(bn256.G1).ScalarBaseMult(big.NewInt(1)),
		new(bn256.G1).ScalarBaseMult(big.NewInt(1)),
		sigmaCred0,
		sigmaCred1,
	}

	jsonSigma, _ := json.Marshal(&sigmaCred)

	return shim.Success(jsonSigma)
}

// deriveshow(phi,usk,avk,sigma_cred,D,m...)
func (s *SmartContract) deriveshow(APIstub shim.ChaincodeStubInterface, args []string) sc.Response {

	if len(args) < 6 {
		return shim.Error("Incorrect number of arguments. Expecting 3")
	}

	PBytes, _ := APIstub.GetState("BLCred_P")
	BLCredP := big.NewInt(0).SetBytes(PBytes)
	// usk := big.NewInt(0).SetBytes([]byte(args[1]))
	var avk RSVK
	json.Unmarshal([]byte(args[2]), &avk)
	// var sigmaCred SIGMA
	// json.Unmarshal([]byte(args[3]), &sigmaCred)

	fbb := new(FBB)
	fbb.Init(BLCredP)
	fbbx, fbby, fbbX, fbbY := fbb.Keygen()
	ptH := string(append(fbbX.Marshal(), fbbY.Marshal()...))

	// bls := new(BLS)
	// bls.Init(BLCredP)
	// sigmas := bls.Sign(usk, ptH)

	// rs := new(RS)
	// rs.Init(BLCredP)
	// sigmad := rs.Derive(avk, sigmaCred, String2D(args[4]), args[5:])

	piNIZK := "BLCredTest"
	m := piNIZK + string(args[0]) + ptH
	sig, r := fbb.Sign(fbbx, fbby, m)
	sigmaShow := SigmaShow{*sig, *r, *fbbX, *fbbY, piNIZK}

	jsonSigmaShow, _ := json.Marshal(&sigmaShow)

	return shim.Success(jsonSigmaShow)
}

// credverify(avk,sigma_show,phi)
func (s *SmartContract) credverify(APIstub shim.ChaincodeStubInterface, args []string) sc.Response {

	if len(args) < 3 {
		return shim.Error("Incorrect number of arguments. Expecting 3")
	}

	PBytes, _ := APIstub.GetState("BLCred_P")
	BLCredP := big.NewInt(0).SetBytes(PBytes)

	var avk RSVK
	json.Unmarshal([]byte(args[0]), &avk)
	var sigmaShow SigmaShow
	json.Unmarshal([]byte(args[1]), &sigmaShow)
	piNIZK := "BLCredTest"
	otsvk := string(append(sigmaShow.X.Marshal(), sigmaShow.Y.Marshal()...))
	m := piNIZK + string(args[2]) + otsvk

	fbb := new(FBB)
	fbb.Init(BLCredP)
	fbb.Verify(&sigmaShow.X, &sigmaShow.Y, m, &sigmaShow.sigma, &sigmaShow.r)

	return shim.Success(nil)
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
