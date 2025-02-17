package pkg

import (
	"log"
	"os"
	"time"

	"github.com/tuneinsight/lattigo/v6/core/rlwe"
	"github.com/tuneinsight/lattigo/v6/multiparty"
	"github.com/tuneinsight/lattigo/v6/schemes/bgv"
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

	l := log.New(os.Stderr, "", 0)

	l.Println("> PublicKeyGen Phase")

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

	l.Printf("\tdone (cloud: %s, Party: %s)\n", elapsedCKGCloud, elapsedCKGParty)

	return pk
}

func RelinearizationKeyGeneration(params ckks.Parameters, crs sampling.PRNG, P []*Party) *rlwe.RelinearizationKey {
	l := log.New(os.Stderr, "", 0)

	l.Println("> RelinearizationKeyGen Phase")

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

	l.Printf("\tdone (cloud: %s, Party: %s)\n", elapsedRKGCloud, elapsedRKGParty)

	return rlk
}

// func Gkgphase(params ckks.Parameters, crs sampling.PRNG, P []*Party) (galKeys []*rlwe.GaloisKey) {

// 	l := log.New(os.Stderr, "", 0)

// 	l.Println("> RTG Phase")

// 	gkg := multiparty.NewGaloisKeyGenProtocol(params) // Rotation keys generation

// 	for _, pi := range P {
// 		pi.gkgShare = gkg.AllocateShare()
// 	}

// 	galEls := append(params.GaloisElementsForInnerSum(1, params.N()>>1), params.GaloisElementForComplexConjugation())
// 	galKeys = make([]*rlwe.GaloisKey, len(galEls))

// 	gkgShareCombined := gkg.AllocateShare()

// 	for i, galEl := range galEls {
// 		l.Println("girdi")
// 		gkgShareCombined.GaloisElement = galEl

// 		crp := gkg.SampleCRP(crs)

// 		elapsedGKGParty += RunTimedParty(func() {
// 			for _, pi := range P {
// 				/* #nosec G601 -- Implicit memory aliasing in for loop acknowledged */
// 				if err := gkg.GenShare(pi.Sk, galEl, crp, &pi.gkgShare); err != nil {
// 					panic(err)
// 				}
// 			}

// 		}, len(P))

// 		elapsedGKGCloud += RunTimed(func() {

// 			if err := gkg.AggregateShares(P[0].gkgShare, P[1].gkgShare, &gkgShareCombined); err != nil {
// 				panic(err)
// 			}

// 			for _, pi := range P[2:] {
// 				if err := gkg.AggregateShares(pi.gkgShare, gkgShareCombined, &gkgShareCombined); err != nil {
// 					panic(err)
// 				}
// 			}

// 			galKeys[i] = rlwe.NewGaloisKey(params)

// 			if err := gkg.GenGaloisKey(gkgShareCombined, crp, galKeys[i]); err != nil {
// 				panic(err)
// 			}
// 		})
// 	}
// 	l.Printf("\tdone (cloud: %s, party %s)\n", elapsedGKGCloud, elapsedGKGParty)

// 	return galKeys
// }

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

	//buffer.RequireSerializerCorrect(t, &P[0].gkgShare)

	galoisKey := rlwe.NewGaloisKey(params)
	gkg[0].GenGaloisKey(P[0].gkgShare, crp, galoisKey)
	return galoisKey
}


// Performs collective public key generation
func CollectiveKeyGenBGV(params bgv.Parameters, crs sampling.PRNG, P []*Party) *rlwe.PublicKey {

	l := log.New(os.Stderr, "", 0)

	l.Println("> PublicKeyGen Phase")

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

	l.Printf("\tdone (cloud: %s, Party: %s)\n", elapsedCKGCloud, elapsedCKGParty)

	return pk
}

func RelinearizationKeyGenerationBGV(params bgv.Parameters, crs sampling.PRNG, P []*Party) *rlwe.RelinearizationKey {
	l := log.New(os.Stderr, "", 0)

	l.Println("> RelinearizationKeyGen Phase")

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

	l.Printf("\tdone (cloud: %s, Party: %s)\n", elapsedRKGCloud, elapsedRKGParty)

	return rlk
}
