package main

import (
	. "encryption/pkg"
	"fmt"

	"github.com/tuneinsight/lattigo/v6/circuits/ckks/bootstrapping"
	"github.com/tuneinsight/lattigo/v6/circuits/ckks/inverse"
	"github.com/tuneinsight/lattigo/v6/circuits/ckks/minimax"

	"github.com/tuneinsight/lattigo/v6/core/rlwe"
	"github.com/tuneinsight/lattigo/v6/schemes/ckks"
	"github.com/tuneinsight/lattigo/v6/utils/sampling"
)


func main() {

	// Set encryption parameters for CKKS
	var err error
	var params ckks.Parameters

	if params, err = ckks.NewParametersFromLiteral(
		ckks.ParametersLiteral{
			LogN: 15,                                     			  				 // log2(ring degree)
			LogQ: []int{55, 45, 45, 45, 45, 45, 45, 45, 45, 45, 45, 45, 45, 45, 45}, // log2(primes Q) (ciphertext modulus)
			LogP:            []int{61},                             				 // log2(primes P) (auxiliary modulus)
			LogDefaultScale: 45,
		}); err != nil {
		panic(err)
	}


	crs, err := sampling.NewKeyedPRNG([]byte{'l', 'a', 't', 't', 'i', 'g', 'o'})
	if err != nil {
		panic(err)
	}

	// Number of parties
	N := 4

	// Create each party and their secret keys
	parties := GenZscoreParties(params, N)

	// See the parties' inputs
	PrintZscorePartyInputs(parties)

	// 1) Collective key generations

	// Collective Public Key
	pk := CollectiveKeyGen(params, crs, parties)

	// Collective Relinearization Key
	rlk := RelinearizationKeyGeneration(params, crs, parties)

	// Evaluation Key
	evk := rlwe.NewMemEvaluationKeySet(rlk) 

	// Refresh Protocol (instance of bootstrapping.Bootstrapper)
	refresher := NewRefresher(params, parties, crs, N)


	// 2) Encryption of each party's float64 values
	inputCiphertexts, numberOfSamplesCiphertexts := EncryptZscoreValues(params, pk, parties)


	// 3) Homomorphic operations for mean calculation

	// Each slot in inputCiphertexts[j] represents the sum of that feature for client j
	// Each slot in numberOfSamplesCiphertexts[j] represents the number of data points for that feature for client j

	// Finding the mean
	// Each slot in mean represents the mean of that feature, each slot in noOfSamplesInverse represents the inverse of total number of data points for that feature 
	mean, noOfSamplesInverse := average(params, inputCiphertexts, numberOfSamplesCiphertexts, evk, refresher, parties)


	// 4) Decryption of the mean and client side operations

	// Decrypting the mean for client side operations
	tsk, tpk := rlwe.NewKeyGenerator(params).GenKeyPairNew()
	
	meanValues := CollectiveDecryption(params, tsk, mean, tpk, parties)

	// Client Side partially summation by using mean sum(for i in range Kj -> (Xi - mean)^2), K is number of data points for Client j
	// Each slot in party[j].TempVarianceSum represents the sum of (Xi - mean)^2 for that feature for client j
	// Each slot in partialSumsCiphertexts[j] represents the encryption of sum of (Xi - mean)^2 for that feature for client j
	partialSumsCiphertexts := clientSidePartialSums(params, meanValues, parties, pk)

	
	// 5) Homomorphic operations for variance calculation

	// Finding the variance
	// Each slot in variance represents the variance of that feature
	// Summing the partial summations that are calculated by the clients then dividing it with the total number of data points
	// variance = 1/N * sum(for i in range N -> (Xi - mean)^2)
	variance := variance(params, partialSumsCiphertexts, mean, noOfSamplesInverse, evk, refresher, parties)


	// 6) Decryption of the variance and printing the results
	tsk2, tpk2 := rlwe.NewKeyGenerator(params).GenKeyPairNew()

	varianceValues := CollectiveDecryption(params, tsk2, variance, tpk2, parties)

	fmt.Printf("\n")
	fmt.Printf("Results:\n")
	fmt.Printf("Mean: ")
	PrintValues(meanValues)

	fmt.Printf("Variance: ")
	PrintValues(varianceValues)

}


// Finding the mean of the encrypted features
// mean = sum(Xi) / N , for each client and feature
func average(params ckks.Parameters, inputCiphertexts []*rlwe.Ciphertext, numberOfSamplesCiphertexts []*rlwe.Ciphertext, evk rlwe.EvaluationKeySet, btp bootstrapping.Bootstrapper, parties []*Party) (mean *rlwe.Ciphertext, noOfSamples *rlwe.Ciphertext ) {
	
	fmt.Printf("\n")
	fmt.Printf("Finding the Mean... \n")

	var err error

	// Evaluator
	eval := ckks.NewEvaluator(params, evk)

	// Minimax evaluator
	minEvl := minimax.NewEvaluator(params, eval, btp)

	// Inverse evaluator
	invEval := inverse.NewEvaluator(params, minEvl)

	// Summing the inputs
	sumInputs := inputCiphertexts[0].CopyNew()
	
	for i := 1; i < len(inputCiphertexts); i++ {
		
		eval.Add(sumInputs, inputCiphertexts[i], sumInputs)

	}


	// Summing the no of samples
	sumNoOfSamples := numberOfSamplesCiphertexts[0].CopyNew()
	for i := 1; i < len(numberOfSamplesCiphertexts); i++ {
		eval.Add(sumNoOfSamples, numberOfSamplesCiphertexts[i], sumNoOfSamples)
	}

	// Inverse of No of samples
	logmin := -30.0
	logmax := 30.0
	var noSamplesInverse *rlwe.Ciphertext
	
	if noSamplesInverse, err = invEval.EvaluatePositiveDomainNew(sumNoOfSamples, logmin, logmax); err != nil {
		panic(err)
	}



	// Bootstrapping the result of inverse
	if noSamplesInverse, err = btp.Bootstrap(noSamplesInverse); err != nil {
		panic(err)
	}


	// Multiply
	var average *rlwe.Ciphertext

	average, err = eval.MulRelinNew(sumInputs, noSamplesInverse)
	if err != nil {
		panic(err)
	}
	if err = eval.Rescale(average, average); err != nil {
		panic(err)
	}

	return average, noSamplesInverse
}

// Calculating the variance of the encrypted features
// 1/N * sum(for i in range N -> (Xi - mean)^2)
func variance(params ckks.Parameters, partialSumsCiphertexts []*rlwe.Ciphertext, mean *rlwe.Ciphertext, noOfSamplesInverse *rlwe.Ciphertext, evk rlwe.EvaluationKeySet, btp bootstrapping.Bootstrapper, parties []*Party) *rlwe.Ciphertext {
	
	fmt.Printf("\n")
	fmt.Printf("Finding the Variance... \n")
	
	var err error
	
	// Evaluator
	eval := ckks.NewEvaluator(params, evk)

	// Summing the partialSums --- sum(for i in range N -> (Xi - mean)^2)
	totalSum := partialSumsCiphertexts[0].CopyNew()
	for i := 1; i < len(partialSumsCiphertexts); i++ {
		eval.Add(totalSum, partialSumsCiphertexts[i], totalSum)
	}


	// Multiply --- variance = 1/N * totalSum
	var variance *rlwe.Ciphertext
	
	variance, err = eval.MulRelinNew(totalSum, noOfSamplesInverse)
	if err != nil {
		panic(err)
	}
	if err = eval.Rescale(variance, variance); err != nil {
		panic(err)
	}

	
	return variance
}

// This is a simulation for client side operation, since the values are not encrypted.
// Each client calculates the sum of (Xi - mean)^2 for each feature
// Later, these partial sums are summed and divided by the total number of data points to calculate variance
func clientSidePartialSums(params ckks.Parameters, mean []float64, parties []*Party, pk *rlwe.PublicKey) ([]*rlwe.Ciphertext){

	// This is a simulation for the operation, values are hand made
	for i, pi := range parties {
		pi.TempVarianceSum = make([]float64, params.MaxSlots())
		for j := range pi.TempVarianceSum {
			if j < 4 {
				pi.TempVarianceSum[j] = (25.0 * float64(i+1)) - (float64(j) * 50.0)
			} else{
				pi.TempVarianceSum[j] = (25.0 * float64(i+1))
			}
		}
	}

	// Encrpyting the results for sending to the cloud
	encryptor := ckks.NewEncryptor(params, pk)
	encoder := ckks.NewEncoder(params)

	partialSumsCiphertexts := make([]*rlwe.Ciphertext, len(parties))
	for i, pi := range parties {
		plaintext := ckks.NewPlaintext(params, params.MaxLevel())

		var err error
		if err = encoder.Encode(pi.TempVarianceSum, plaintext); err != nil {
			panic(err)
		}
		if partialSumsCiphertexts[i], err = encryptor.EncryptNew(plaintext); err != nil {
			panic(err)
		}
	}

	return partialSumsCiphertexts	
}
