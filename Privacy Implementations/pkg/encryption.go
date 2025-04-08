package pkg

import (
	"time"

	"github.com/tuneinsight/lattigo/v6/core/rlwe"
	"github.com/tuneinsight/lattigo/v6/schemes/ckks"
)

var elapsedEncryptParty time.Duration
var elapsedEncryptCloud time.Duration


// Encrypts each Party's Input values for z score computation
func EncryptZscoreValues(params ckks.Parameters, pk *rlwe.PublicKey, parties []*Party) ([]*rlwe.Ciphertext, []*rlwe.Ciphertext) {
	encryptor := ckks.NewEncryptor(params, pk)
	encoder := ckks.NewEncoder(params)

	inputCiphertexts := make([]*rlwe.Ciphertext, len(parties))
	for i, pi := range parties {
		plaintext := ckks.NewPlaintext(params, params.MaxLevel())

		var err error
		if err = encoder.Encode(pi.Input, plaintext); err != nil {
			panic(err)
		}
		if inputCiphertexts[i], err = encryptor.EncryptNew(plaintext); err != nil {
			panic(err)
		}
	}

	numberOfSamplesCiphertexts := make([]*rlwe.Ciphertext, len(parties))
	for i, pi := range parties {
		plaintext := ckks.NewPlaintext(params, params.MaxLevel())

		var err error
		if err = encoder.Encode(pi.NumberOfSamples, plaintext); err != nil {
			panic(err)
		}
		if numberOfSamplesCiphertexts[i], err = encryptor.EncryptNew(plaintext); err != nil {
			panic(err)
		}
	}

	return inputCiphertexts, numberOfSamplesCiphertexts
}

// Encrypts each Party's Input values for minmax computation
func EncryptMinMaxValues(params ckks.Parameters, pk *rlwe.PublicKey, parties []*Party) ([]*rlwe.Ciphertext, []*rlwe.Ciphertext) {
	encryptor := ckks.NewEncryptor(params, pk)
	encoder := ckks.NewEncoder(params)

	maxCiphertexts := make([]*rlwe.Ciphertext, len(parties))
	for i, pi := range parties {
		
		plaintext := ckks.NewPlaintext(params, params.MaxLevel())

		var err error
		if err = encoder.Encode(pi.MaxValues, plaintext); err != nil {
			panic(err)
		}
		if maxCiphertexts[i], err = encryptor.EncryptNew(plaintext); err != nil {
			panic(err)
		}

	}

	minCiphertexts := make([]*rlwe.Ciphertext, len(parties))
	for i, pi := range parties {
		plaintext := ckks.NewPlaintext(params, params.MaxLevel())

		var err error
		if err = encoder.Encode(pi.MinValues, plaintext); err != nil {
			panic(err)
		}
		if minCiphertexts[i], err = encryptor.EncryptNew(plaintext); err != nil {
			panic(err)
		}
	}

	return minCiphertexts, maxCiphertexts
}

// Encrypts each Party's Number Of Samples values for Robust Scaling computation
func EncryptRobustSampleValues(params ckks.Parameters, pk *rlwe.PublicKey, parties []*Party) []*rlwe.Ciphertext {
	encryptor := ckks.NewEncryptor(params, pk)
	encoder := ckks.NewEncoder(params)

	numberOfSamplesCiphertexts := make([]*rlwe.Ciphertext, len(parties))
	for i, pi := range parties {
		plaintext := ckks.NewPlaintext(params, params.MaxLevel())

		var err error
		if err = encoder.Encode(pi.RobustScalingNSamples, plaintext); err != nil {
			panic(err)
		}
		if numberOfSamplesCiphertexts[i], err = encryptor.EncryptNew(plaintext); err != nil {
			panic(err)
		}
	}

	return numberOfSamplesCiphertexts
}

// Encrypts each Party's number of Left and Right values for Robust Scaling computation
func EncryptRobustLRValues(params ckks.Parameters, pk *rlwe.PublicKey, parties []*Party) ([]*rlwe.Ciphertext, []*rlwe.Ciphertext) {
	encryptor := ckks.NewEncryptor(params, pk)
	encoder := ckks.NewEncoder(params)

	lCounts := make([]*rlwe.Ciphertext, len(parties))
	for i, pi := range parties {
		plaintext := ckks.NewPlaintext(params, params.MaxLevel())

		var err error
		if err = encoder.Encode(pi.RobustScalingLCount, plaintext); err != nil {
			panic(err)
		}
		if lCounts[i], err = encryptor.EncryptNew(plaintext); err != nil {
			panic(err)
		}
	}

	rCounts := make([]*rlwe.Ciphertext, len(parties))
	for i, pi := range parties {
		plaintext := ckks.NewPlaintext(params, params.MaxLevel())

		var err error
		if err = encoder.Encode(pi.RobustScalingRCount, plaintext); err != nil {
			panic(err)
		}
		if rCounts[i], err = encryptor.EncryptNew(plaintext); err != nil {
			panic(err)
		}
	}

	return lCounts, rCounts
}


// Encrypts one array of float64 values
func EncryptOneValue(params ckks.Parameters, pk *rlwe.PublicKey, value []float64) *rlwe.Ciphertext {
	encryptor := ckks.NewEncryptor(params, pk)
	encoder := ckks.NewEncoder(params)

	plaintext := ckks.NewPlaintext(params, params.MaxLevel())

	var err error
	if err = encoder.Encode(value, plaintext); err != nil {
		panic(err)
	}
	ciphertext, err := encryptor.EncryptNew(plaintext)
	if err != nil {
		panic(err)
	}

	return ciphertext
}