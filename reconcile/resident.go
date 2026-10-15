package reconcile

import (
	"math/bits"
)

// StrataCount is the number of estimator strata.
const StrataCount = 32

// StratumCapacity is the extraction capacity maintained in each estimator stratum.
const StratumCapacity = 8

// ResidentKernel is the per-population reconciliation state.
type ResidentKernel struct {
	accumulator RoomAccumulator
	strata      [StrataCount][StratumCapacity]uint64
}

// NewResidentKernel creates empty resident state.
func NewResidentKernel() ResidentKernel {
	return ResidentKernel{accumulator: NewRoomAccumulator()}
}

// Accumulator returns the level-0 room accumulator.
func (r *ResidentKernel) Accumulator() RoomAccumulator {
	return r.accumulator
}

// Strata returns the estimator's odd syndrome coordinates by stratum.
func (r *ResidentKernel) Strata() *[StrataCount][StratumCapacity]uint64 {
	return &r.strata
}

// Insert adds one element to the reconciled population.
func (r *ResidentKernel) Insert(hash ElementHash) error {
	if hash.H64 == 0 {
		return ErrZeroShortIdentifier
	}
	if err := r.accumulator.Insert(hash); err != nil {
		return err
	}
	toggleStratum(&r.strata, strataIdentifier(hash))
	return nil
}

// Remove removes one element from the reconciled population.
func (r *ResidentKernel) Remove(hash ElementHash) error {
	if hash.H64 == 0 {
		return ErrZeroShortIdentifier
	}
	if err := r.accumulator.Remove(hash); err != nil {
		return err
	}
	toggleStratum(&r.strata, strataIdentifier(hash))
	return nil
}

func strataIdentifier(hash ElementHash) uint64 {
	if hash.Q3 != 0 {
		return hash.Q3
	}
	// Preserve manually assembled legacy values that omit Q3; canonical hashes
	// from FromDigest32 always carry the explicit zero-to-one Q3 mapping.
	if hash.H64 != 0 {
		return hash.H64
	}
	return 1
}

func toggleStratum(strata *[StrataCount][StratumCapacity]uint64, value uint64) {
	index := bits.TrailingZeros64(value)
	if index >= StrataCount {
		index = StrataCount - 1
	}
	squared := Mul(value, value)
	oddPower := value
	for i := 0; i < StratumCapacity; i++ {
		strata[index][i] ^= oddPower
		oddPower = Mul(oddPower, squared)
	}
}
