package main

import (
	"fmt"

	// "github.com/hyperledger/fabric/core/chaincode/shim"
	// sc "github.com/hyperledger/fabric/protos/peer"
	"github.com/hyperledger/fabric-chaincode-go/shim"
	sc "github.com/hyperledger/fabric-protos-go/peer"
)

type SmartContract struct {
}

func (s *SmartContract) Init(APIstub shim.ChaincodeStubInterface) sc.Response {
	return shim.Success(nil)
}

// setup()
func (s *SmartContract) setup(APIstub shim.ChaincodeStubInterface) sc.Response {
	return shim.Success(nil)
}

// authkeygen(n)
func (s *SmartContract) authkeygen(APIstub shim.ChaincodeStubInterface, args []string) sc.Response {
	return shim.Success(nil)
}

// ukeygen()
func (s *SmartContract) ukeygen(APIstub shim.ChaincodeStubInterface) sc.Response {
	return shim.Success(nil)
}

// issuecred(usk,uvk,m,ask,avk)
func (s *SmartContract) issuecred(APIstub shim.ChaincodeStubInterface, args []string) sc.Response {
	return shim.Success(nil)
}

// deriveshow(phi,usk,avk,sigma_cred,D)
func (s *SmartContract) deriveshow(APIstub shim.ChaincodeStubInterface, args []string) sc.Response {
	return shim.Success(nil)
}

// credverify(avk,sigma_show,phi)
func (s *SmartContract) credverify(APIstub shim.ChaincodeStubInterface, args []string) sc.Response {
	return shim.Success(nil)
}

func main() {
	err := shim.Start(new(SmartContract))
	if err != nil {
		fmt.Printf("Error creating new Smart Contract: %s", err)
	}
}
