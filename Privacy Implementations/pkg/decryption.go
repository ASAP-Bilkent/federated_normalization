package pkg

import (
	"time"

	"github.com/tuneinsight/lattigo/v6/core/rlwe"
	"github.com/tuneinsight/lattigo/v6/multiparty"
	"github.com/tuneinsight/lattigo/v6/ring"
	"github.com/tuneinsight/lattigo/v6/schemes/ckks"
)

var elapsedPCKSCloud time.Duration
var elapsedPCKSParty time.Duration


// enable decryption for outside Party who has tsk
func PcksPhase(params ckks.Parameters, tpk *rlwe.PublicKey, encRes *rlwe.Ciphertext, P []*Party) (encOut *rlwe.Ciphertext) {

	// Collective key switching from the collective secret key to
	// the target public key
	sigmaSmudging := 8 * rlwe.DefaultNoise
	pcks, err := multiparty.NewPublicKeySwitchProtocol(params, ring.DiscreteGaussian{Sigma: sigmaSmudging, Bound: 6 * sigmaSmudging})
	if err != nil {
		panic(err)
	}

	for _, pi := range P {
		pi.pcksShare = pcks.AllocateShare(params.MaxLevel())
	}


	elapsedPCKSParty = RunTimedParty(func() {
		for _, pi := range P {
			/* #nosec G601 -- Implicit memory aliasing in for loop acknowledged */
			pcks.GenShare(pi.Sk, tpk, encRes, &pi.pcksShare)
		}
	}, len(P))

	pcksCombined := pcks.AllocateShare(params.MaxLevel())
	encOut = ckks.NewCiphertext(params, 1, params.MaxLevel())
	elapsedPCKSCloud = RunTimed(func() {
		for _, pi := range P {
			if err = pcks.AggregateShares(pi.pcksShare, pcksCombined, &pcksCombined); err != nil {
				panic(err)
			}
		}

		pcks.KeySwitch(encRes, pcksCombined, encOut)
	})

	return
}

// Decrypts and prints the result
func CollectiveDecryption(params ckks.Parameters, tsk *rlwe.SecretKey, ciphertext *rlwe.Ciphertext, tpk *rlwe.PublicKey, parties []*Party) (result []float64) {
	// Decryptor
	dec := rlwe.NewDecryptor(params, tsk)

	encOut := PcksPhase(params, tpk, ciphertext, parties)

	// Encoder
	ecd := ckks.NewEncoder(params)

	// Decrypt
	plaintext := dec.DecryptNew(encOut)

	// Decode
	values := make([]float64, params.MaxSlots())
	if err := ecd.Decode(plaintext, values); err != nil {
		panic(err)
	}

	return values
}

// Decrypts and prints the result
func TestCollectiveDecryption(params ckks.Parameters, ciphertext *rlwe.Ciphertext, parties []*Party) {

	tsk, tpk := rlwe.NewKeyGenerator(params).GenKeyPairNew()

	values := CollectiveDecryption(params, tsk, ciphertext, tpk, parties)

	PrintValues(values)

}

func IdealSecretKeyDecryption(params ckks.Parameters, ciphertext *rlwe.Ciphertext, P []*Party) (result []float64){
	// Ideal Key Generation
	skIdealOut := rlwe.NewSecretKey(params)
	for _, pi := range P {
		params.RingQ().Add(skIdealOut.Value.Q, pi.Sk.Value.Q, skIdealOut.Value.Q)
	}
	decryptor := rlwe.NewDecryptor(params, skIdealOut)
	encoder := ckks.NewEncoder(params)


	plaintext := decryptor.DecryptNew(ciphertext)
	// Decode
	values := make([]float64, params.MaxSlots())
	if err := encoder.Decode(plaintext, values); err != nil {
		panic(err)
	}

	// PrintValues(values)
	return values
}

func TestIdealSecretKeyDecryption(params ckks.Parameters, ciphertext *rlwe.Ciphertext, P []*Party) {
	// Ideal Key Generation
	skIdealOut := rlwe.NewSecretKey(params)
	for _, pi := range P {
		params.RingQ().Add(skIdealOut.Value.Q, pi.Sk.Value.Q, skIdealOut.Value.Q)
	}
	decryptor := rlwe.NewDecryptor(params, skIdealOut)
	encoder := ckks.NewEncoder(params)


	plaintext := decryptor.DecryptNew(ciphertext)
	// Decode
	values := make([]float64, params.MaxSlots())
	if err := encoder.Decode(plaintext, values); err != nil {
		panic(err)
	}

	PrintValues(values)
}