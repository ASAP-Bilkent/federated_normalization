package pkg

import (
	"time"

	"github.com/tuneinsight/lattigo/v6/core/rlwe"
	"github.com/tuneinsight/lattigo/v6/multiparty"
	"github.com/tuneinsight/lattigo/v6/schemes/ckks"
	"github.com/tuneinsight/lattigo/v6/utils/sampling"
)

var elapsedCKGCloud time.Duration
var elapsedCKGParty time.Duration
var elapsedRKGCloud time.Duration
var elapsedRKGParty time.Duration
var elapsedGKGCloud time.Duration
var elapsedGKGParty time.Duration

// Performs collective public key generation
func CollectiveKeyGen(params ckks.Parameters, crs sampling.PRNG, P []*Party) *rlwe.PublicKey {

	ckg := multiparty.NewPublicKeyGenProtocol(params) // Public key generation
	ckgCombined := ckg.AllocateShare()
	for _, pi := range P {
		pi.ckgShare = ckg.AllocateShare()
	}

	crp := ckg.SampleCRP(crs)

	elapsedCKGParty = RunTimedParty(func() {
		for _, pi := range P {
			/* #nosec G601 -- Implicit memory aliasing in for loop acknowledged */
			ckg.GenShare(pi.Sk, crp, &pi.ckgShare)
		}
	}, len(P))

	pk := rlwe.NewPublicKey(params)

	elapsedCKGCloud = RunTimed(func() {
		for _, pi := range P {
			ckg.AggregateShares(pi.ckgShare, ckgCombined, &ckgCombined)
		}
		ckg.GenPublicKey(ckgCombined, crp, pk)
	})

	return pk
}

func RelinearizationKeyGeneration(params ckks.Parameters, crs sampling.PRNG, P []*Party) *rlwe.RelinearizationKey {

	rkg := multiparty.NewRelinearizationKeyGenProtocol(params) // Relineariation key generation

	_, rkgCombined1, rkgCombined2 := rkg.AllocateShare()

	for _, pi := range P {
		pi.rlkEphemSk, pi.rkgShareOne, pi.rkgShareTwo = rkg.AllocateShare()
	}

	crp := rkg.SampleCRP(crs)

	elapsedRKGParty = RunTimedParty(func() {
		for _, pi := range P {
			/* #nosec G601 -- Implicit memory aliasing in for loop acknowledged */
			rkg.GenShareRoundOne(pi.Sk, crp, pi.rlkEphemSk, &pi.rkgShareOne)
		}
	}, len(P))

	elapsedRKGCloud = RunTimed(func() {
		for _, pi := range P {
			/* #nosec G601 -- Implicit memory aliasing in for loop acknowledged */
			rkg.AggregateShares(pi.rkgShareOne, rkgCombined1, &rkgCombined1)
		}
	})

	elapsedRKGParty += RunTimedParty(func() {
		for _, pi := range P {
			/* #nosec G601 -- Implicit memory aliasing in for loop acknowledged */
			rkg.GenShareRoundTwo(pi.rlkEphemSk, pi.Sk, rkgCombined1, &pi.rkgShareTwo)
		}
	}, len(P))

	rlk := rlwe.NewRelinearizationKey(params)
	elapsedRKGCloud += RunTimed(func() {
		for _, pi := range P {
			/* #nosec G601 -- Implicit memory aliasing in for loop acknowledged */
			rkg.AggregateShares(pi.rkgShareTwo, rkgCombined2, &rkgCombined2)
		}
		rkg.GenRelinearizationKey(rkgCombined1, rkgCombined2, rlk)
	})

	return rlk
}


func Gkgphase2(params ckks.Parameters, crs sampling.PRNG, P []*Party, N int) (galKeys *rlwe.GaloisKey) {
	
	gkg := make([]multiparty.GaloisKeyGenProtocol, N)
	for i := range gkg {
		if i == 0 {
			gkg[i] = multiparty.NewGaloisKeyGenProtocol(params)
		} else {
			gkg[i] = gkg[0].ShallowCopy()
		}
	}

	for i, pi := range P {
		pi.gkgShare = gkg[i].AllocateShare()
	}

	crp := gkg[0].SampleCRP(crs)

	galEl := params.GaloisElementForComplexConjugation()

	for i, pi := range P {
		gkg[i].GenShare(pi.Sk, galEl, crp, &pi.gkgShare)
	}

	for i, pi := range P {
		if i != 0 {
			gkg[0].AggregateShares(P[0].gkgShare, pi.gkgShare, &P[0].gkgShare)
		}
	}

	galoisKey := rlwe.NewGaloisKey(params)
	gkg[0].GenGaloisKey(P[0].gkgShare, crp, galoisKey)
	return galoisKey
}
