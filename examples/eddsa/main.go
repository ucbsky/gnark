package main

import (
	"fmt"
	"math/rand"
	"math/big"
	"time"
	"bytes"
	"github.com/consensys/gnark/frontend"
	"github.com/consensys/gnark/std/signature/eddsa"
	"github.com/consensys/gnark/std/hash/mimc"
	tedwards "github.com/consensys/gnark-crypto/ecc/twistededwards"
	"github.com/consensys/gnark-crypto/ecc"
	"github.com/consensys/gnark/backend/groth16"
	"github.com/consensys/gnark/frontend/cs/r1cs"
	"github.com/consensys/gnark-crypto/hash"
	"github.com/consensys/gnark/std/algebra/native/twistededwards"
	eddsaCrypto "github.com/consensys/gnark-crypto/signature/eddsa"
	"github.com/consensys/gnark-crypto/signature"
	//eddsa2 "github.com/consensys/gnark-crypto/ecc/bn254/twistededwards/eddsa"
)


type eddsaCircuit struct {
	curveID   tedwards.ID
	PublicKey []eddsa.PublicKey           `gnark:",public"`
	Signature []eddsa.Signature           `gnark:",public"`
	Message   []frontend.Variable         `gnark:",public"`
}

func initCircuit(N int) eddsaCircuit {
	return eddsaCircuit{
		PublicKey: make([]eddsa.PublicKey, N),
		Signature: make([]eddsa.Signature, N),
		Message:   make([]frontend.Variable, N),
	}
}

func (circuit *eddsaCircuit) Define(api frontend.API) error {
	curve, err := twistededwards.NewEdCurve(api, circuit.curveID)
	if err != nil {
		return err
	}

	//mimc, err := mimc.NewMiMC(api)
	//if err != nil {
	//	return err
	//}

	for i := 0; i < len(circuit.PublicKey); i++ {
		mimc, err := mimc.NewMiMC(api)
		if err != nil {
			return err
		}
		ver_err := eddsa.Verify(curve, circuit.Signature[i], circuit.Message[i], circuit.PublicKey[i], &mimc)
		if ver_err != nil {
			return ver_err
		}
	}

	return nil
	//return eddsa.Verify(curve, circuit.Signature, circuit.Message, circuit.PublicKey, &mimc)
}

func runtrial(N int) {
    // instantiate hash function
    hFunc := hash.MIMC_BLS12_377.New()

    seed := time.Now().Unix()
    randomness := rand.New(rand.NewSource(seed))

    // create a eddsa key pair
    //for i := 0; i < N; i++ {
    var privateKeys []signature.Signer = make([]signature.Signer, N);
    var publicKeys []signature.PublicKey = make([]signature.PublicKey, N);
    var msgs []big.Int = make([]big.Int, N);
    var signatures [][]byte = make([][]byte, N);
    var err error
    snarkField, err := twistededwards.GetSnarkField(tedwards.BLS12_377)
    for i := 0; i<N; i++ {
	    privateKeys[i], err = eddsaCrypto.New(tedwards.BLS12_377, randomness)
	    if err != nil {
		return
	    }
	    publicKeys[i] = privateKeys[i].Public()
	    msgs[i].Rand(randomness, snarkField)
	    msgDataUnpadded := msgs[i].Bytes()
	    msgData := make([]byte, len(snarkField.Bytes()))
	    copy(msgData[len(msgData) - len(msgDataUnpadded):], msgDataUnpadded)
	    //msgs[i] = []byte{4, 138, 238, 31, 227, 139, 149, 17, 139, 42, 141, 190, 58, 89, 207, 213, 43, 102, 126, 255, 120, 144, 82, 112, 31, 116, 76, 42, 1, 122, 145, 41}
	    signatures[i], err = privateKeys[i].Sign(msgData, hFunc)
	    if err != nil {
		return
	    }
	    isValid, err := publicKeys[i].Verify(signatures[i], msgData, hFunc)
	    if err != nil {
		return
	    }
	    if !isValid {
	        fmt.Println("1. invalid signature")
	    } else {
	        //fmt.Println("1. valid signature")
	    }
    }


    // note that the message is on 4 bytes
    //msg := []byte{4, 138, 238, 31, 227, 139, 149, 17, 139, 42, 141, 190, 58, 89, 207, 213, 43, 102, 126, 255, 120, 144, 82, 112, 31, 116, 76, 42, 1, 122, 145, 41}
    //This message errors, not sure why: {0xde, 0xad, 0xf0, 0x0d}
    //fmt.Println(msg)
    // sign the message
    //signature, err := privateKey.Sign(msg, hFunc)


    // verifies signature
    /*
    isValid, err := publicKey.Verify(signature, msg, hFunc)
    if !isValid {
        fmt.Println("1. invalid signature")
    } else {
        fmt.Println("1. valid signature")
    }
    */

    var circuit eddsaCircuit = initCircuit(N)
    circuit.curveID = tedwards.BLS12_377
    _r1cs, err := frontend.Compile(ecc.BLS12_377.ScalarField(), r1cs.NewBuilder, &circuit)
    if err != nil {
	    fmt.Println("error cannot be returned 1")
	   // return err[0]
    }

    var buf bytes.Buffer
    _, _ = _r1cs.WriteTo(&buf)

    newR1CS := groth16.NewCS(ecc.BLS12_377)
    _, _ = newR1CS.ReadFrom(&buf)

    pk, vk, err := groth16.Setup(_r1cs)
    if err != nil {
	    fmt.Println("error cannot be returned 2")
	    //return err
    }

    // declare the witness
    var assignment eddsaCircuit = initCircuit(N)

    // assign message value
    msgs2 := make([]frontend.Variable, N)
    //[N]frontend.Variable{msgs[0], msgs[1]}
    //for _, x := range msgs {
    for i := 0; i < N; i++ {
	msgs2[i] = msgs[i]
//	msgs2 = append(msgs2, msgs[i])
    }
    copy(assignment.Message[:], msgs2)
    //assignment.Message = [N]frontend.Variable{msgs[0], msgs[1]}

    // public key bytes
    var _publicKeys [][]byte = make([][]byte, N)
    for i := 0; i < N; i++ {
	    _publicKeys[i] = publicKeys[i].Bytes()
	    _publicKeys[i] = _publicKeys[i][:32]
	    assignment.PublicKey[i].Assign(tedwards.BLS12_377, _publicKeys[i])
	    assignment.Signature[i].Assign(tedwards.BLS12_377, signatures[i])
    }

    // assign public key values
    //assignment.PublicKey = assignment.PublicKey[0].Assign(tedwards.BN254, _publicKeys, N)

    // assign signature values
    //assignment.Signature.Assign(tedwards.BN254, signatures)

    // witness
    witness, err := frontend.NewWitness(&assignment, ecc.BLS12_377.ScalarField(), frontend.PublicOnly())
    publicWitness, err := witness.Public()
    fmt.Println("Here2!")

    //err = test.IsSolved(circuit, witness)

    // generate the proof
    startTime := time.Now()
    proof, err := groth16.Prove(_r1cs, pk, witness)
    //endTime := time.Now()

    proveTime := time.Since(startTime)

    fmt.Printf("Prove time: %v\n", proveTime)

    // verify the proof
    err = groth16.Verify(proof, vk, publicWitness)
    if err != nil {
      //   invalid proof
    }
}

func main() {
	for i := 0; i < 3; i++ {
		for p := 0; p <= 3; p++ {
			n := 1 << p
			fmt.Println("TESTING WITH TRIAL = ", i+1)
			fmt.Println("TESTING WITH N = ", n)
			runtrial(n)
		}
	}
}
