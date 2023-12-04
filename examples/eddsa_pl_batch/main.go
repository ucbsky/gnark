package main

import (
	"fmt"
	"log"
	"math/rand"
	"math/big"
	"time"
	//"bytes"
	"sync"
	"github.com/consensys/gnark/frontend"
	//groth16_bn254 "github.com/consensys/gnark/backend/groth16/bn254"
//	cs "github.com/consensys/gnark/constraint/bn254"
	"github.com/consensys/gnark/constraint"
	"github.com/consensys/gnark/backend/witness"
	"github.com/consensys/gnark/std/signature/eddsa"
	"github.com/consensys/gnark/std/hash/mimc"
	tedwards "github.com/consensys/gnark-crypto/ecc/twistededwards"
	"github.com/consensys/gnark-crypto/ecc"
	"github.com/consensys/gnark/backend/plonk"
	"github.com/consensys/gnark/frontend/cs/scs"
	"github.com/consensys/gnark-crypto/hash"
	"github.com/consensys/gnark/std/algebra/native/twistededwards"
	eddsaCrypto "github.com/consensys/gnark-crypto/signature/eddsa"
	"github.com/consensys/gnark-crypto/signature"
	"github.com/consensys/gnark/test"
	cs "github.com/consensys/gnark/constraint/bls12-377"
	//eddsa2 "github.com/consensys/gnark-crypto/ecc/bn254/twistededwards/eddsa"
)

const N = 1 << 9
const batch = 2

type eddsaCircuit struct {
	curveID   tedwards.ID
	PublicKey eddsa.PublicKey           `gnark:",public"`
	Signature eddsa.Signature           `gnark:",public"`
	Message   frontend.Variable         `gnark:",public"`
}

func (circuit *eddsaCircuit) Define(api frontend.API) error {
	curve, err := twistededwards.NewEdCurve(api, circuit.curveID)
	if err != nil {
		return err
	}

	mimc, err := mimc.NewMiMC(api)
	if err != nil {
		return err
	}

	//for i := 0; i < N; i++ {
	//	mimc, err := mimc.NewMiMC(api)
	//	if err != nil {
	//		return err
	//	}
	//return eddsa.Verify(curve, circuit.Signature, circuit.Message, circuit.PublicKey, &mimc)
		//if ver_err != nil {
		//	return ver_err
		//}
	//}

	//return nil
	return eddsa.Verify(curve, circuit.Signature, circuit.Message, circuit.PublicKey, &mimc)
}

func runtrial(N int, batch int) {
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

    var circuit eddsaCircuit
    circuit.curveID = tedwards.BLS12_377
    ccs, err := frontend.Compile(ecc.BLS12_377.ScalarField(), scs.NewBuilder, &circuit)
    if err != nil {
	    fmt.Println("error cannot be returned 1")
	   // return err[0]
    }

    _r1cs := ccs.(*cs.SparseR1CS)
    srs, err := test.NewKZGSRS(_r1cs)
    if err != nil {
	    fmt.Println("error cannot be returned 2")
	    //return err
    }
    // public key bytes
    var _publicKeys [][]byte = make([][]byte, N)
    for i := 0; i < N; i++ {
	    _publicKeys[i] = publicKeys[i].Bytes()
	    _publicKeys[i] = _publicKeys[i][:32]
    }

    // declare the witness
    var assignment []eddsaCircuit = make([]eddsaCircuit, N)
    var witnessFull_arr []witness.Witness = make([]witness.Witness, N)
    var witnessPub_arr []witness.Witness = make([]witness.Witness, N)
    for n := 0; n < N; n++ {
	assignment[n].Message = msgs[n]



    // assign message value
    //msgs2 := make([]frontend.Variable, N)
    //[N]frontend.Variable{msgs[0], msgs[1]}
    //for _, x := range msgs {
   // for i := 0; i < N; i++ {
//	msgs2[i] = msgs[i]
//	msgs2 = append(msgs2, msgs[i])
  //  }
    //copy(assignment.Message[:], msgs2)
    //assignment.Message = [N]frontend.Variable{msgs[0], msgs[1]}

    assignment[n].PublicKey.Assign(tedwards.BLS12_377, _publicKeys[n])
    assignment[n].Signature.Assign(tedwards.BLS12_377, signatures[n])

    // assign public key values
    //assignment.PublicKey = assignment.PublicKey[0].Assign(tedwards.BN254, _publicKeys, N)

    // assign signature values
    //assignment.Signature.Assign(tedwards.BN254, signatures)

    // witness
    witnessFull_arr[n], err = frontend.NewWitness(&assignment[n], ecc.BLS12_377.ScalarField())
    if err != nil {
	    return
    }
    witnessPub_arr[n], err = frontend.NewWitness(&assignment[n], ecc.BLS12_377.ScalarField(), frontend.PublicOnly())
    if err != nil {
	    return
    }

    //err = test.IsSolved(circuit, witness)
}

    startTime := time.Now()
    pk, vk, err := plonk.Setup(ccs, srs)
    setupTime := time.Since(startTime)
    if err != nil {
	    log.Fatal(err)
    }
    fmt.Printf("Setup time: %v\n", setupTime)
    // generate the proof
    sum := time.Duration(0)
    c := make(chan plonk.Proof)
    var wg sync.WaitGroup
    //wg.Add(batch)
    for i := 0; i < N; i+=batch {
//	fmt.Printf("for loop: %s\n", sum)
	startTime := time.Now()
	for j := 0; j < batch; j++ {
		wg.Add(1)
	/*	go func(_r1cs constraint.ConstraintSystem, pk groth16.ProvingKey, witness_arr[i+j] witness.Witness) {
			defer wg.Done()
			groth16.Prove(_r1cs, pk, witness_arr[i+j])
		} (groth16.Proof, err)*/
		go run(ccs, pk, witnessFull_arr[i+j], c, &wg)
	}
	wg.Wait()
    	//proof, err := groth16.Prove(_r1cs, pk, witness_arr[i])
        proveTime := time.Since(startTime)
	sum += proveTime
	for j := 0; j < batch; j++ {
		proof := <-c
		err = plonk.Verify(proof, vk, witnessPub_arr[i+j])
        	if err != nil {
            		//   invalid proof
        	}
	}
}

    //endTime := time.Now()


    fmt.Printf("Total Prove time: %v\n", sum)

    // verify the proof
}

func run(ccs constraint.ConstraintSystem, pk plonk.ProvingKey, fullWitness witness.Witness, c chan plonk.Proof, wg *sync.WaitGroup) {
//	defer wg.Done()
	proof, err := plonk.Prove(ccs, pk, fullWitness)
	if err != nil {
		return
	}
	wg.Done()
	c <- proof
}


func main() {
	for i := 0; i < 3; i++ {
		for pb := 0; pb <= 0; pb++ {
			for pn := pb; pn <= 10; pn++ {
				n := 1 << pn
				batch := 1 << pb
				//fmt.Println("TESTING WITH TRIAL = ", i+1)
				fmt.Println("TESTING WITH N = ", n)
				fmt.Println("TESTING WITH BATCH = ", batch)
				runtrial(n, batch)
			}
		}
	}
}
