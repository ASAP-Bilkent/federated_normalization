package pkg

import (
	"fmt"
	"math"
	"time"
)

func Check(err error) {
	if err != nil {
		panic(err)
	}
}

func RunTimed(f func()) time.Duration {
	start := time.Now()
	f()
	return time.Since(start)
}

func RunTimedParty(f func(), N int) time.Duration {
	start := time.Now()
	f()
	return time.Duration(time.Since(start).Nanoseconds() / int64(N))
}

func PrintValues(values []float64) {
	for i := 0; i < 4; i++ {
		fmt.Printf("%20.15f ", values[i])
	}
	fmt.Printf("...\n")
}

func PrintZscorePartyInputs(parties []*Party) {
	for i, pi := range parties {

		fmt.Printf("Party %d\n", i)
		fmt.Printf("Input: ")

		for i := 0; i < 4; i++ {
			fmt.Printf("%5.5f ", float64(pi.Input[i]))
		}

		fmt.Printf("...\n")

		fmt.Printf("number of samples: ")

		for i := 0; i < 4; i++ {
			fmt.Printf("%5.2f ", float64(pi.NumberOfSamples[i]))
		}

		fmt.Printf("...\n")
		fmt.Printf("\n")
	}
}

func PrintMinMaxPartyInputs(parties []*Party) {
	for i, pi := range parties {

		fmt.Printf("Party %d\n", i)
		fmt.Printf("MinValues: ")

		for i := 0; i < 4; i++ {
			fmt.Printf("%5.5f ", float64(pi.MinValues[i]))
		}

		fmt.Printf("...\n")

		fmt.Printf("MaxValues: ")

		for i := 0; i < 4; i++ {
			fmt.Printf("%5.2f ", float64(pi.MaxValues[i]))
		}

		fmt.Printf("...\n")
		fmt.Printf("\n")
	}
}

func PrintRobustPartyInputs(parties []*Party) {
	for i, pi := range parties {

		fmt.Printf("Party %d\n", i)
		fmt.Printf("NoOfSamples: ")

		for i := 0; i < len(pi.RobustScalingNSamples); i++ {
			fmt.Printf("%d ", int64(math.Round(pi.RobustScalingNSamples[i])))
		}
		
		fmt.Printf("\n")
		fmt.Printf("Data: \n")

		for i := 0; i < len(pi.RobustScalingInput); i++ {
			for j := 0; j < len(pi.RobustScalingInput[i]); j++ {
				fmt.Printf("%2.2f ", float64(pi.RobustScalingInput[i][j]))
			}
			fmt.Printf("\n")
		}

		fmt.Printf("\n")
	}
}