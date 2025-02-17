package main

import (
	. "encryption/pkg"
	"fmt"

	"github.com/tuneinsight/lattigo/v6/circuits/ckks/bootstrapping"
	"github.com/tuneinsight/lattigo/v6/circuits/ckks/comparison"
	"github.com/tuneinsight/lattigo/v6/circuits/ckks/minimax"
	"github.com/tuneinsight/lattigo/v6/core/rlwe"
	"github.com/tuneinsight/lattigo/v6/schemes/ckks"
	"github.com/tuneinsight/lattigo/v6/utils/sampling"
)


func main() {
	// Set encryption parameters for CKKS
	var err error
	var params ckks.Parameters

	// 128-bit secure parameters enabling depth-14 circuits.
	// LogN:15
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
	N := 10

	// Create each party and their secret keys
	parties := GenMinMaxParties(params, N)

	// See the parties' inputs
	PrintMinMaxPartyInputs(parties)

	// 1) Collective key generations

	// Collective Public Key
	pk := CollectiveKeyGen(params, crs, parties)

	// Collective Relinearization Key
	rlk := RelinearizationKeyGeneration(params, crs, parties)

	// Collective GaloisKeys generation
	galKeys := Gkgphase2(params, crs, parties, N)

	// Evaluation Key
	evk := rlwe.NewMemEvaluationKeySet(rlk, galKeys) 

	// Refresh Protocol (instance of bootstrapping.Bootstrapper)
	refresher := NewRefresher(params, parties, crs, N)

	fmt.Printf("Min Level %d \n", refresher.MinimumInputLevel())
	fmt.Printf("Max Level %d \n", params.MaxLevel())

	// 2) Encryption of each party's float64 values
	minCiphertexts, maxCiphertexts := EncryptMinMaxValues(params, pk, parties)

	// 3) Homomorphic operations for finding min and max values
	minResults, maxResults := findMinMax(params, minCiphertexts, maxCiphertexts, evk, refresher, parties)

	fmt.Printf("Min Result: \n")
	TestCollectiveDecryption(params, minResults, parties)
	fmt.Printf("Max Result: \n")
	TestCollectiveDecryption(params, maxResults, parties)

}


func findMinMax(params ckks.Parameters, minCiphertexts []*rlwe.Ciphertext, maxCiphertexts []*rlwe.Ciphertext, evk rlwe.EvaluationKeySet, btp bootstrapping.Bootstrapper, parties []*Party) (minResults *rlwe.Ciphertext, maxResults *rlwe.Ciphertext ) {
	
	fmt.Printf("\n")
	fmt.Printf("Normalizing the data... \n")
	
	var err error

	// Evaluator
	eval := ckks.NewEvaluator(params, evk)

	// Minimax evaluator
	minimaxEvl := minimax.NewEvaluator(params, eval, btp)

	// Default polynomial for the comparison
	polys := minimax.NewPolynomial(comparison.DefaultCompositePolynomialForSign)

	// Comparison evaluator
	CmpEval := comparison.NewEvaluator(params, minimaxEvl, polys)
	
	normalizationFactor1 := 10000.0 // (1/10000)
	normalizationFactor2 := 1000.0 // (1/1000)

	// Normalize each feature based on given max values. In this case we fill with even number features with max values of normalizationFactor1 and odd number features with max values of normalizationFactor2
	normalizationVector := make([]float64, params.MaxSlots())
	for i := range normalizationVector {
		if i % 2 == 0 {
			normalizationVector[i] = 1/normalizationFactor1
		} else{
			normalizationVector[i] = 1/normalizationFactor2
		}
		
	}


	// Normalize each feature of every client's min max inputs
	minCiphertextsNormalized := make([]*rlwe.Ciphertext, len(minCiphertexts))
	for i := range minCiphertextsNormalized {
		minCiphertextsNormalized[i], err = eval.MulRelinNew(minCiphertexts[i], normalizationVector)
		if err != nil {
			panic(err)
		}
		if err = eval.Rescale(minCiphertextsNormalized[i], minCiphertextsNormalized[i]); err != nil {
			panic(err)
		}
	}

	maxCipherTextsNormalized := make([]*rlwe.Ciphertext, len(maxCiphertexts))
	for i := range maxCipherTextsNormalized {
		maxCipherTextsNormalized[i], err = eval.MulRelinNew(maxCiphertexts[i], normalizationVector)
		if err != nil {
			panic(err)
		}
		if err = eval.Rescale(maxCipherTextsNormalized[i], maxCipherTextsNormalized[i]); err != nil {
			panic(err)
		}
	}


	fmt.Printf("\n")
	fmt.Printf("Finding the Min... \n")
	// Finding the min value
	var min *rlwe.Ciphertext
	for i := range minCiphertextsNormalized {
		if i == 0 {
			min = minCiphertextsNormalized[i].CopyNew()
		} else {
			min, err = CmpEval.Min(min, minCiphertextsNormalized[i])
			if err != nil {
				panic(err)
			}
		}
		min, _ = btp.Bootstrap(min)
	}

	// fmt.Printf("Minim Level %d \n", min.Level())

	fmt.Printf("\n")
	fmt.Printf("Finding the Max... \n")
	// Finding the max value
	var max *rlwe.Ciphertext
	for i := range maxCipherTextsNormalized {
		if i == 0 {
			max = maxCipherTextsNormalized[i].CopyNew()
		} else {
			max, err = CmpEval.Max(max, maxCipherTextsNormalized[i])
			if err != nil {
				panic(err)
			}
		}
		max, _ = btp.Bootstrap(max)
	}

	min, _ = btp.Bootstrap(min)
	max, _ = btp.Bootstrap(max)
	// fmt.Printf("Maxim Level %d \n", max.Level())


	// Renormalizing the min and max values
	reverseNormalizationVector := make([]float64, params.MaxSlots())
	for i := range reverseNormalizationVector {
		if i % 2 == 0 {
			reverseNormalizationVector[i] = normalizationFactor1
		} else{
			reverseNormalizationVector[i] = normalizationFactor2
		}
		
	}

	var normalizedMin *rlwe.Ciphertext
	normalizedMin, err = eval.MulRelinNew(min, reverseNormalizationVector)
	if err != nil {
		panic(err)
	}
	if err = eval.Rescale(normalizedMin, normalizedMin); err != nil {
		panic(err)
	}

	var normalizedMax *rlwe.Ciphertext
	normalizedMax, err = eval.MulRelinNew(max, reverseNormalizationVector)
	if err != nil {
		panic(err)
	}
	if err = eval.Rescale(normalizedMax, normalizedMax); err != nil {
		panic(err)
	}


	return normalizedMin, normalizedMax
}
