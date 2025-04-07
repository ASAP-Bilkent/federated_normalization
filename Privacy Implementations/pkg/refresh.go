package pkg

import (
	"fmt"

	"github.com/tuneinsight/lattigo/v6/core/rlwe"
	"github.com/tuneinsight/lattigo/v6/multiparty/mpckks"
	"github.com/tuneinsight/lattigo/v6/schemes/ckks"
	"github.com/tuneinsight/lattigo/v6/utils/sampling"
)

type Refresher struct {
	Parties []*Party
	N int
	crs sampling.PRNG
	params ckks.Parameters
}

func NewRefresher(params ckks.Parameters, parties []*Party, crs sampling.PRNG, N int) *Refresher {
	return &Refresher{Parties: parties, N: N, crs: crs, params: params}
}

// Bootstrap implements the single-ciphertext bootstrapping
func (refresher *Refresher) Bootstrap(ct *rlwe.Ciphertext) (*rlwe.Ciphertext, error) {
	if ct.Level() < refresher.GetMinRefreshLevel() {
		return nil, fmt.Errorf("ciphertext level too low")
	}
	return refresher.RefreshProtocol(refresher.params, refresher.crs, ct, refresher.Parties, refresher.N)
}

// BootstrapMany implements bootstrapping for a slice of ciphertexts
func (refresher Refresher) BootstrapMany(cts []rlwe.Ciphertext) ([]rlwe.Ciphertext, error) {
	results := make([]rlwe.Ciphertext, len(cts))
	for i, ct := range cts {
		if ct.Level() < refresher.GetMinRefreshLevel() {
			return nil, fmt.Errorf("ciphertext at index %d has level too low", i)
		}
		encOut, err := refresher.RefreshProtocol(refresher.params, refresher.crs, &ct, refresher.Parties, refresher.N)
		if err != nil {
			return nil, err
		}
		results[i] = *encOut
			
	}
	return results, nil
}

// Depth returns the number of levels consumed by the bootstrapping circuit
func (refresher Refresher) Depth() int {
	return 0
}

// MinimumInputLevel returns the minimum level required for bootstrapping
func (refresher Refresher) MinimumInputLevel() int {
	return refresher.GetMinRefreshLevel()
}

// OutputLevel defines the level after bootstrapping
func (refresher Refresher) OutputLevel() int {
	return refresher.params.MaxLevel()
}

// Refreshing function for testing purposes
func (refresher Refresher) Refresh(encOut *rlwe.Ciphertext)	(*rlwe.Ciphertext, error) {
	return refresher.RefreshProtocol(refresher.params, refresher.crs, encOut, refresher.Parties, refresher.N)
}

// GetMinRefreshLevel returns the minimum level required for bootstrapping
func (refresher Refresher) GetMinRefreshLevel() (int) {
	minLevel, _, ok := mpckks.GetMinimumLevelForRefresh(128, refresher.params.DefaultScale(), refresher.N, refresher.params.Q())
	if ok {
		return minLevel
	} else {
		fmt.Printf("refresh error: not enough level to ensure correctness and 128 bit security")
		return -1
	}
}


func (refresher Refresher) RefreshProtocol(params ckks.Parameters, crs sampling.PRNG, ciphertext *rlwe.Ciphertext, P []*Party, N int) (encOut *rlwe.Ciphertext, err error) {

	minLevel, logBound, ok := mpckks.GetMinimumLevelForRefresh(128, params.DefaultScale(), N, params.Q())
	if ok {
		for i, pi := range P {

			var err error
			if i == 0 {
				if pi.RefreshProtocol, err = mpckks.NewRefreshProtocol(params, logBound, params.Xe()); err != nil {
					panic(err)
				}
			} else {
				pi.RefreshProtocol = P[0].RefreshProtocol.ShallowCopy()
			}

			pi.refreshShare = pi.AllocateShare(minLevel, params.MaxLevel())
		}

		P0 := P[0]
		crp := P0.SampleCRP(params.MaxLevel(), crs)

		for i, p := range P {
			p.GenShare(p.Sk, logBound, ciphertext, crp, &p.refreshShare)

			if i > 0 {
				P0.AggregateShares(&p.refreshShare, &P0.refreshShare, &P0.refreshShare)
			}
		}

		encOut := ckks.NewCiphertext(params, 1, params.MaxLevel())
		P0.Finalize(ciphertext, crp, P0.refreshShare, encOut)

		return encOut, nil
	} else {
		return nil, fmt.Errorf("refresh error: not enough level to ensure correctness and 128 bit security")
	}

}
