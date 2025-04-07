package main

import (
	. "encryption/pkg"
	"fmt"
	"math"
	"sort"
	"time"

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
	NFeatures := 4
	Percentile := 50.0

	// Create each party and their secret keys
	parties := GenRobustParties(params, N, NFeatures)

	// See the parties' inputs
	PrintRobustPartyInputs(parties)

	// 1) Collective key generations

	// Collective Public Key
	pk := CollectiveKeyGen(params, crs, parties)

	// Collective Relinearization Key
	rlk := RelinearizationKeyGeneration(params, crs, parties)

	// Evaluation Key
	evk := rlwe.NewMemEvaluationKeySet(rlk)

	// 2) Encrypting the input number of samples
	numberOfSamplesCiphertexts := EncryptRobustSampleValues(params, pk, parties)


	fmt.Printf("\n")
	fmt.Printf("Finding Total No Of Samples... \n")
	noOfSamples := encryptedSum(params, evk, numberOfSamplesCiphertexts)

	tsk, tpk := rlwe.NewKeyGenerator(params).GenKeyPairNew()
	noOfSamplesValues := CollectiveDecryption(params, tsk, noOfSamples, tpk, parties)

	fmt.Printf("\n")
	fmt.Printf("Total No Of Samples: \n")
	intNoOfSamplesValues := make([]int64, NFeatures)
	for i := 0; i < NFeatures; i++ {
		intNoOfSamplesValues[i] = int64(math.Round(noOfSamplesValues[i]))
		fmt.Printf("%d ", intNoOfSamplesValues[i])
	}
	fmt.Printf("\n")


	// Small epsilon to define floating-point precision, one can decide the compute limit based on the application. It can be different for each feature's requirements
	epsilon := make([]float64, NFeatures)

	// We can assume that we calculated the global min and max values from the minmax.go
	globalMin := make([]float64, NFeatures)
	globalMax := make([]float64, NFeatures)

	for i := 0; i < NFeatures; i++ {
		globalMin[i] = -2.0
		globalMax[i] = 2.0
		epsilon[i] = 0.000001
	}


	// Finding the median's index for each feature, this can be changed to %75 or %25 for other robust scaling values
	k := make([]int64, NFeatures)
	isValidIndex := make([]bool, NFeatures)
	for i := 0; i < NFeatures; i++ {
		// Dividing the number of samples by 2 to find median index
		tempK := 1 + float64(Percentile / 100.0) * float64(intNoOfSamplesValues[i] - 1)
		
		if tempK == math.Floor(tempK){
			k[i] = int64(tempK)
			isValidIndex[i] = true
		} else {
			k[i] = int64(math.Floor(tempK))
			isValidIndex[i] = false
		}

	}

	// Finding the medians 
	start := time.Now()
	fmt.Printf("\nFinding the k-th element... \n")
	results := findKthElement(params, pk, evk, k, NFeatures, globalMin, globalMax, epsilon, intNoOfSamplesValues, parties, isValidIndex)

	fmt.Printf("\n")
	fmt.Printf("Results: \n")
	for i := 0; i < NFeatures; i++ {
		fmt.Printf("%2.8f ", results[i])
	}
	timeCalculated := time.Since(start)
	fmt.Printf("\n")
	fmt.Printf("%s\n", timeCalculated)


	fmt.Printf("\n")
	fmt.Printf("\n")
	fmt.Printf("Validation:")
	validationResults := validationArrays(parties, NFeatures)
	for i := 0; i < NFeatures; i++ {
		fmt.Printf("\n")
		fmt.Printf("Feature %d: \n", i)
		for _, val := range validationResults[i] {
			fmt.Printf("%2.8f ", val)
		}
	}


}


func encryptedSum(params ckks.Parameters, evk rlwe.EvaluationKeySet, inputCiphertext []*rlwe.Ciphertext) (result *rlwe.Ciphertext){

	eval := ckks.NewEvaluator(params, evk)

	sum := inputCiphertext[0].CopyNew()
	for i := 1; i < len(inputCiphertext); i++ {
		eval.Add(sum, inputCiphertext[i], sum)
	}

	return sum
}

func findKthElement(params ckks.Parameters, pk *rlwe.PublicKey, evk rlwe.EvaluationKeySet, k []int64, NFeatures int, min []float64, max []float64, epsilon []float64, totalNoSamples []int64, parties []*Party, isValidIndex []bool) (result []float64){

	// This array is used to check if we have found the k-th element for each feature
	checkEveryFeature := make([]bool, NFeatures)

	a := make([]float64, len(min))
	b := make([]float64, len(max))

	copy(a, min)
	copy(b, max)
	

	m := make([]float64, NFeatures)
	results := make([]float64, NFeatures)

	for !allTrue(checkEveryFeature) {

		for i := 0; i < NFeatures; i++ {
			if checkEveryFeature[i] {
				continue
			}

			// Calculating the midpoints for each feature, this is a server side operation, no need of communication
			m[i] = (a[i] + b[i]) / 2.0
		}

		// Count elements smaller and greater than midpoint in all parties for every feature in one communication round
		lCount, gCount := communicationRound(params, pk, parties, m, NFeatures, evk)

		for i := 0; i < NFeatures; i++ {
			if checkEveryFeature[i] {
				continue
			}

			// // Check if interested index (k) is a valid index or average of two elements, this feature can be disabled.
			if !isValidIndex[i] {
				// Check if m is the kth element for feature i
				// In this part, we want to find the element that is between two elements since k is not a valid index (like finding median (k=5) for 10)
				if lCount[i] <= k[i] && gCount[i] <= totalNoSamples[i]-k[i] {
					fmt.Printf("The %d-th ranked element for feature %d is: %2.8f\n", k[i], i, m[i])
					results[i] = m[i]
					checkEveryFeature[i] = true
					continue
				}

				// Adjust range
				if lCount[i] >= k[i] {
					b[i] = m[i]
				} else {
					a[i] = m[i]
				}

				// This is a computation limit, epsilon is defined based on the application's needs
				if b[i]-a[i] <= epsilon[i] {
					results[i] = (a[i]+b[i])/2.0
					fmt.Printf("*The %d-th ranked element for feature %d is: %2.8f\n", k[i], i, m[i])
					checkEveryFeature[i] = true
				}

			} else {
				// Check if m is the kth element for feature i
				// Only difference in this is we look at k-1 instead of k, because k is a valid index, we want to find the exact k-th element (like finding median (k=5) for 9)
				if lCount[i] <= k[i]-1 && gCount[i] <= totalNoSamples[i]-k[i] {
					fmt.Printf("The %d-th ranked element for feature %d is: %2.8f\n", k[i], i, m[i])
					results[i] = m[i]
					checkEveryFeature[i] = true
					continue
				}

				// Adjust range
				if lCount[i] >= k[i] {
					b[i] = m[i]
				} else {
					a[i] = m[i]
				}

				// This is a computation limit, epsilon is defined based on the application's needs
				if b[i]-a[i] <= epsilon[i] {
					results[i] = (a[i]+b[i])/2.0
					fmt.Printf("*The %d-th ranked element for feature %d is: %2.8f\n", k[i], i, m[i])
					checkEveryFeature[i] = true
				}				
			}

		}

	}

	return results
}


// Count elements smaller and greater than midpoint in all parties for every feature
func communicationRound(params ckks.Parameters, pk *rlwe.PublicKey, parties []*Party, m []float64, NFeatures int, evk rlwe.EvaluationKeySet) ([]int64 , []int64) {

	// Individual calculation for parties
	calculatePartysCounts(parties, m, NFeatures)

	// Encryption of the parties' counts
	lCountCiphertexts, rCountCiphertexts := EncryptRobustLRValues(params, pk, parties)

	// Summing the encrypted counts
	totalLCountCiphertext := encryptedSum(params, evk, lCountCiphertexts)
	totalRCountCiphertext := encryptedSum(params, evk, rCountCiphertexts)

	// Decryption of the total counts
	tsk, tpk := rlwe.NewKeyGenerator(params).GenKeyPairNew()
	totalLCountValues := CollectiveDecryption(params, tsk, totalLCountCiphertext, tpk, parties)
	totalRCountValues := CollectiveDecryption(params, tsk, totalRCountCiphertext, tpk, parties)

	intTotalLCountValues := make([]int64, NFeatures)
	intTotalRCountValues := make([]int64, NFeatures)
	for i := 0; i < NFeatures; i++ {
		intTotalRCountValues[i] = int64(math.Round(totalRCountValues[i]))
		intTotalLCountValues[i] = int64(math.Round(totalLCountValues[i]))
	}



	return intTotalLCountValues, intTotalRCountValues
}

// This is a client side individual computation, this function simulates it
func calculatePartysCounts(parties []*Party, m []float64, NFeatures int) {

	// Reseting the RobustScalingLCount and RobustScalingRCount for the new round
	for _, pi := range parties {
		pi.RobustScalingLCount = make([]float64, NFeatures)
		pi.RobustScalingRCount = make([]float64, NFeatures)
	}

	// Count elements smaller and greater than midpoint in all parties (this is individual calculation for parties, not summed yet)
	for _, pi := range parties {
		for i, featureData := range pi.RobustScalingInput {
			for _, val := range featureData {
				if val < m[i] {
					pi.RobustScalingLCount[i]++
				} else if val > m[i] {
					pi.RobustScalingRCount[i]++
				}
			}
		}
	}

}

func allTrue(arr []bool) bool {
	for _, val := range arr {
		if !val {
			return false
		}
	}
	return true
}

// Calculating the sorted and merged arrays for validating the results
func validationArrays(parties []*Party, NFeatures int) [][]float64 {

	if len(parties) == 0 {
		return nil
	}
	
	// Create a merged array for each feature
	merged := make([][]float64, NFeatures)
	
	// Collect values for each feature
	for _, party := range parties {
		for featureIdx, values := range party.RobustScalingInput {
			merged[featureIdx] = append(merged[featureIdx], values...)
		}
	}

	// Sort each merged feature array
	for i := range merged {
		sort.Float64s(merged[i])
	}

	return merged
}