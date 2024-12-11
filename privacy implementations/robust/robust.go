package main

import (
	. "encryption/pkg"
	"fmt"
	"sort"

	"github.com/tuneinsight/lattigo/v6/core/rlwe"
	"github.com/tuneinsight/lattigo/v6/schemes/bgv"
	"github.com/tuneinsight/lattigo/v6/utils/sampling"
)


func main() {
	// Set encryption parameters for CKKS
	var err error
	var params bgv.Parameters

	// 128-bit secure parameters enabling depth-7 circuits.
	// LogN:14, LogQP: 431.
	params, err = bgv.NewParametersFromLiteral(bgv.ParametersLiteral{
		LogN:             14,
		LogQ:             []int{56, 55, 55, 54, 54, 54},
		LogP:             []int{55, 55},
		PlaintextModulus: 65537,
	})

	crs, err := sampling.NewKeyedPRNG([]byte{'l', 'a', 't', 't', 'i', 'g', 'o'})
	
	if err != nil {
		panic(err)
	}

	// Number of parties
	N := 4
	NFeatures := 4

	// Create each party and their secret keys
	parties := GenRobustParties(params, N, NFeatures)

	// See the parties' inputs
	PrintRobustPartyInputs(parties)

	// 1) Collective key generations

	// Collective Public Key
	pk := CollectiveKeyGenBGV(params, crs, parties)

	// Collective Relinearization Key
	rlk := RelinearizationKeyGenerationBGV(params, crs, parties)

	// Evaluation Key
	evk := rlwe.NewMemEvaluationKeySet(rlk)

	// 2) Encrypting the input number of samples
	numberOfSamplesCiphertexts := EncryptRobustSampleValues(params, pk, parties)


	fmt.Printf("\n")
	fmt.Printf("Finding Total No Of Samples... \n")
	noOfSamples := encryptedSum(params, evk, numberOfSamplesCiphertexts)

	tsk, tpk := rlwe.NewKeyGenerator(params).GenKeyPairNew()
	noOfSamplesValues := CollectiveDecryptionBGV(params, tsk, noOfSamples, tpk, parties)

	fmt.Printf("\n")
	fmt.Printf("Total No Of Samples: \n")
	for i := 0; i < NFeatures; i++ {
		fmt.Printf("%d ", int64(noOfSamplesValues[i]))
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
		epsilon[i] = 0.0001
	}


	// Finding the median's index for each feature, this can be changed to %75 or %25 for other robust scaling values
	k := make([]int64, NFeatures)
	for i := 0; i < NFeatures; i++ {
		// Dividing the number of samples by 2 to find median index
		k[i] = ceilDiv(noOfSamplesValues[i], 2)
	}

	// Finding the medians
	fmt.Printf("\nFinding the median... \n")
	results := findKthElement(params, pk, evk, k, NFeatures, globalMin, globalMax, epsilon, noOfSamplesValues, parties)

	fmt.Printf("\n")
	fmt.Printf("Results: \n")
	for i := 0; i < NFeatures; i++ {
		fmt.Printf("%.5f ", results[i])
	}
	fmt.Printf("\n")
	fmt.Printf("\n")
	fmt.Printf("Validation:")
	validationResults := validationArrays(parties, NFeatures)
	for i := 0; i < NFeatures; i++ {
		fmt.Printf("\n")
		fmt.Printf("Feature %d: \n", i)
		for _, val := range validationResults[i] {
			fmt.Printf("%.5f ", val)
		}
	}

}


func encryptedSum(params bgv.Parameters, evk rlwe.EvaluationKeySet, inputCiphertext []*rlwe.Ciphertext) (result *rlwe.Ciphertext){

	eval := bgv.NewEvaluator(params, evk)

	sum := inputCiphertext[0].CopyNew()
	for i := 1; i < len(inputCiphertext); i++ {
		eval.Add(sum, inputCiphertext[i], sum)
	}

	return sum
}

func findKthElement(params bgv.Parameters, pk *rlwe.PublicKey, evk rlwe.EvaluationKeySet, k []int64, NFeatures int, min []float64, max []float64, epsilon []float64, totalNoSamples []int64, parties []*Party) (result []float64){

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

		for i := 0; i < NFeatures; i++ {
			if checkEveryFeature[i] {
				continue
			}


			// Count elements smaller and greater than midpoint in all parties for every feature in one communication round
			lCount, gCount := communicationRound(params, pk, parties, m, NFeatures, evk)


			// Check if interested index (k) is a valid index or average of two elements, this can be disabled.
			if totalNoSamples[i] % k[i] == 0 {
				// Check if m is the kth element for feature i
				if lCount[i] <= k[i] && gCount[i] <= totalNoSamples[i]-k[i] {
					fmt.Printf("The %d-th ranked element for feature %d is: %.5f\n", k[i], i, m[i])
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
					fmt.Printf("*The %d-th ranked element for feature %d is: %.5f\n", k[i], i, m[i])
					checkEveryFeature[i] = true
				}

			} else {
				// Check if m is the kth element for feature i
				if lCount[i] <= k[i]-1 && gCount[i] <= totalNoSamples[i]-k[i] {
					fmt.Printf("The %d-th ranked element for feature %d is: %.5f\n", k[i], i, m[i])
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
					fmt.Printf("*The %d-th ranked element for feature %d is: %.5f\n", k[i], i, m[i])
					checkEveryFeature[i] = true
				}				
			}

		}

	}

	return results
}


// Count elements smaller and greater than midpoint in all parties for every feature
func communicationRound(params bgv.Parameters, pk *rlwe.PublicKey, parties []*Party, m []float64, NFeatures int, evk rlwe.EvaluationKeySet) ([]int64 , []int64) {

	// Individual calculation for parties
	calculatePartysCounts(parties, m, NFeatures)

	// Encryption of the parties' counts
	lCountCiphertexts, rCountCiphertexts := EncryptRobustLRValues(params, pk, parties)

	// Summing the encrypted counts
	totalLCountCiphertext := encryptedSum(params, evk, lCountCiphertexts)
	totalRCountCiphertext := encryptedSum(params, evk, rCountCiphertexts)

	// Decryption of the total counts
	tsk, tpk := rlwe.NewKeyGenerator(params).GenKeyPairNew()
	totalLCountValues := CollectiveDecryptionBGV(params, tsk, totalLCountCiphertext, tpk, parties)
	totalRCountValues := CollectiveDecryptionBGV(params, tsk, totalRCountCiphertext, tpk, parties)


	return totalLCountValues, totalRCountValues
}

// This is a client side individual computation, this function simulates it
func calculatePartysCounts(parties []*Party, m []float64, NFeatures int) {

	// Reseting the RobustScalingLCount and RobustScalingRCount for the new round
	for _, pi := range parties {
		pi.RobustScalingLCount = make([]int64, NFeatures)
		pi.RobustScalingRCount = make([]int64, NFeatures)
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

func ceilDiv(x, y int64) int64 {
	return (x + y - 1) / y
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