package pkg

import (
	"math/rand"

	"github.com/tuneinsight/lattigo/v6/core/rlwe"
	"github.com/tuneinsight/lattigo/v6/multiparty"
	"github.com/tuneinsight/lattigo/v6/multiparty/mpckks"
	"github.com/tuneinsight/lattigo/v6/schemes/ckks"
	//"math/rand"
)

type Party struct {
	mpckks.RefreshProtocol
	Sk         *rlwe.SecretKey
	rlkEphemSk *rlwe.SecretKey

	ckgShare     multiparty.PublicKeyGenShare
	gkgShare    multiparty.GaloisKeyGenShare
	rkgShareOne  multiparty.RelinearizationKeyGenShare
	rkgShareTwo  multiparty.RelinearizationKeyGenShare
	//cksShare     multiparty.KeySwitchShare
	pcksShare    multiparty.PublicKeySwitchShare
	refreshShare multiparty.RefreshShare

	Input           []float64
	NumberOfSamples []float64
	TempVarianceSum []float64
	MinValues     []float64
	MaxValues     []float64

	RobustScalingNSamples []float64
	RobustScalingInput [][]float64
	RobustScalingLCount []float64
	RobustScalingRCount []float64

	//decryptionShare *rlwe.Plaintext // Add this field
}

// Generates parties and their secret keys for z score computation
func GenZscoreParties(params ckks.Parameters, N int) []*Party {
	kgen := rlwe.NewKeyGenerator(params)
	parties := make([]*Party, N)

	for i := 0; i < N; i++ {
		pi := &Party{}
		pi.Sk = kgen.GenSecretKeyNew() // Generate secret key for each party

		pi.Input = make([]float64, params.MaxSlots())
		for j := range pi.Input {
			if j < 4 {
				pi.Input[j] = (10000.0 * float64(i+1)) - (float64(j) * 500.0) // Each party holds a float64 value for Input (e.g., 10.0, 20.0) for all slots
			} else{
				pi.Input[j] = 10000.0 * float64(i+1) // Each party holds a float64 value for Input (e.g., 10.0, 20.0) for all slots
			}
		}

		pi.NumberOfSamples = make([]float64, params.MaxSlots())
		for j := range pi.NumberOfSamples {
			if j < 4 {
				pi.NumberOfSamples[j] = (200.0 * float64(i+1)) + (float64(j) * 50.0)  // Each party holds a float64 value NumberOfSamples (e.g., 2.0, 4.0) for all slots
			} else{
				pi.NumberOfSamples[j] = 200.0 * float64(i+1) // Each party holds a float64 value NumberOfSamples (e.g., 2.0, 4.0) for all slots
			}
			
		}

		parties[i] = pi
	}
	return parties
}

// Generates parties and their secret keys for minmax computation
func GenMinMaxParties(params ckks.Parameters, N int) []*Party {
	kgen := rlwe.NewKeyGenerator(params)
	parties := make([]*Party, N)

	min1, max1 := -99.0, 99.0
	min2, max2 := -999.0, 999.0
    
	for i := 0; i < N; i++ {
		pi := &Party{}
		pi.Sk = kgen.GenSecretKeyNew() // Generate secret key for each party

		pi.MinValues = make([]float64, params.MaxSlots())
		for j := range pi.MinValues {
			//pi.MinValues[j] = -5.0 * float64(i+1) + 10 // Each party holds a float64 value for Input (e.g., 10.0, 20.0) for all slots
			//random float64 value dependent on j
			if j % 2 == 0 {
				pi.MinValues[j] = min2 + rand.Float64()*(max2-min2)
			} else{
				pi.MinValues[j] = min1 + rand.Float64()*(max1-min1)
			}

		}

		pi.MaxValues = make([]float64, params.MaxSlots())
		for j := range pi.MaxValues {
			if j == 0{
				pi.MaxValues[j] = 0.1001 * float64(i)
			}else if j % 2 == 0 {
				pi.MaxValues[j] = min2 + rand.Float64()*(max2-min2)
			} else{
				pi.MaxValues[j] = min1 + rand.Float64()*(max1-min1)
			}
			// if j < 4 {
			// 	pi.MaxValues[j] = -100.0 * float64(i+1) // Each party holds a float64 value NumberOfSamples (e.g., 2.0, 4.0) for all slots
			// } else{
			// 	pi.MaxValues[j] = -100.0 * float64(i+1)
			// }
		}

		parties[i] = pi
	}
	return parties
}

// Generates parties and their secret keys for k-th element (robust scaling) computation
func GenRobustParties(params ckks.Parameters, N int, NFeatures int) []*Party {
	kgen := rlwe.NewKeyGenerator(params)
	parties := make([]*Party, N)

	maxLength := 4

	min1, max1 := -2.0, 2.0
    
	for i := 0; i < N; i++ {
		pi := &Party{}
		pi.Sk = kgen.GenSecretKeyNew() // Generate secret key for each party

		pi.RobustScalingInput = make([][]float64, NFeatures)
		pi.RobustScalingNSamples = make([]float64, NFeatures)
		for j := 0; j < NFeatures; j++ {
			length := rand.Intn(maxLength) + 1
			array := make([]float64, length)

			for k := 0; k < length; k++ {
				array[k] = min1 + rand.Float64()*(max1-min1)
			}

			pi.RobustScalingInput[j] = array
			pi.RobustScalingNSamples[j] = float64(int64(length))
		}

		parties[i] = pi
	}
	return parties
}