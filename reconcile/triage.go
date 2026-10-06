package reconcile

import "errors"

// MaxBucketedSketchCapacity is the maximum sum of capacities in one bucketed sketch request.
const MaxBucketedSketchCapacity = 4096

// MaxBucketSketchCapacity is the maximum extraction capacity assigned to one bucket.
const MaxBucketSketchCapacity = 32

// BucketRequest describes one localized sketch request.
type BucketRequest struct {
	// Depth is the binary-tree depth of the request.
	Depth uint8
	// Prefix is the binary prefix at the given depth.
	Prefix uint32
	// Capacity is the extraction capacity requested for this bucket.
	Capacity int
}

// BucketDecodeSuccess captures one independently decoded bucket.
type BucketDecodeSuccess struct {
	// Depth is the binary-tree depth of the decoded bucket.
	Depth uint8
	// Prefix is the binary prefix at the given depth.
	Prefix uint32
	// Roots are the decoded short identifiers for the bucket.
	Roots []uint64
}

// FailedBucket records a bucket that exceeded decode capacity.
type FailedBucket struct {
	// Depth is the binary-tree depth of the failed bucket.
	Depth uint8
	// Prefix is the binary prefix at the given depth.
	Prefix uint32
}

// BucketDecodeBatch is the partial result of concatenated bucket decoding.
type BucketDecodeBatch struct {
	// SuccessfulBuckets lists the decoded buckets in request order.
	SuccessfulBuckets []BucketDecodeSuccess
	// FailedBuckets lists buckets that must be retried or split.
	FailedBuckets []FailedBucket
}

// ValidateBucketRequests checks capacity limits and antichain ordering.
func ValidateBucketRequests(requests []BucketRequest) error {
	totalCapacity := 0
	var previousEnd uint64

	for _, req := range requests {
		if req.Capacity <= 0 || req.Capacity > MaxBucketSketchCapacity {
			return ErrInvalidSketchCapacity
		}
		if req.Depth > 32 {
			return ErrInvalidBucketIndex
		}
		if req.Depth < 32 && req.Prefix >= (uint32(1)<<req.Depth) {
			return ErrInvalidBucketIndex
		}

		totalCapacity += req.Capacity
		if totalCapacity > MaxBucketedSketchCapacity {
			return ErrInvalidSketchCapacity
		}

		shift := 32 - req.Depth
		start := uint64(req.Prefix) << shift
		end := start + (uint64(1) << shift)
		if start < previousEnd {
			return ErrInvalidBucketIndex
		}
		previousEnd = end
	}

	return nil
}

// SaturatedDeltaEstimate is the estimator's saturated sentinel, returned when
// even the sparsest residual stratum overflows.
const SaturatedDeltaEstimate = uint64(8) << 31

// overCapacityDeltaFloor is the minimum cardinality implied by an
// over-capacity stratum-0 decode failure.
const overCapacityDeltaFloor = uint64(StratumCapacity) + 1

// StrataEstimate is the structured result of the strata estimator.
type StrataEstimate struct {
	// Delta is the estimated symmetric-difference cardinality.
	Delta uint64
	// LowConfidence reports that decoding stopped at an over-capacity stratum
	// and the delta was extrapolated from the already-decoded tail.
	LowConfidence bool
}

// EstimateStrata estimates the symmetric difference from the resident strata.
//
// Starting at the sparsest stratum it decodes the longest consecutive tail. If
// `r` is the lowest decoded stratum and `T` the decoded tail cardinality,
// `T * 2^r` estimates the complete difference; decoding every stratum yields
// the exact cardinality. If even the sparsest residual stratum overflows the
// estimate is extrapolated from the decoded tail and marked
// [StrataEstimate.LowConfidence].
func EstimateStrata(
	local *[StrataCount][StratumCapacity]uint64,
	remote *[StrataCount][StratumCapacity]uint64,
) (StrataEstimate, error) {
	work := maxFactorWork
	var decodedTail uint64
	lowestDecoded := -1

	for stratum := StrataCount - 1; stratum >= 0; stratum-- {
		var residual [StratumCapacity]uint64
		for i := 0; i < StratumCapacity; i++ {
			residual[i] = local[stratum][i] ^ remote[stratum][i]
		}
		roots, err := decodePinSketch(residual[:], StratumCapacity, &work)
		if err != nil {
			// coverage:ignore
			if !errors.Is(err, ErrDecodeFailure) {
				return StrataEstimate{}, err
			}
			if lowestDecoded < 0 && stratum == StrataCount-1 {
				return StrataEstimate{Delta: SaturatedDeltaEstimate, LowConfidence: true}, nil
			}
			scaled := stratum
			if lowestDecoded >= 0 {
				scaled = lowestDecoded
			}
			tail := decodedTail
			if tail < overCapacityDeltaFloor {
				tail = overCapacityDeltaFloor
			}
			return StrataEstimate{Delta: saturatingShifted(tail, scaled), LowConfidence: true}, nil
		}
		decodedTail += uint64(len(roots))
		lowestDecoded = stratum
	}

	// coverage:ignore
	if lowestDecoded < 0 {
		return StrataEstimate{}, nil
	}
	return StrataEstimate{Delta: saturatingShifted(decodedTail, lowestDecoded)}, nil
}

// saturatingShifted returns value << shift, saturating to the maximum uint64.
func saturatingShifted(value uint64, shift int) uint64 {
	// coverage:ignore
	if shift < 0 {
		return 0
	}
	// coverage:ignore
	if shift >= 64 {
		if value == 0 {
			return 0
		}
		return ^uint64(0)
	}
	factor := uint64(1) << uint(shift)
	if value > ^uint64(0)/factor {
		return ^uint64(0)
	}
	return value * factor
}

// EstimateDelta estimates the symmetric difference from the resident strata.
//
// This is the compatibility form of [EstimateStrata]: the returned bool reports
// whether an estimate is available. Budget exhaustion is reported as
// (0, false, nil); other errors are returned unchanged. Callers that need the
// low-confidence signal should use [EstimateStrata].
func EstimateDelta(
	local *[StrataCount][StratumCapacity]uint64,
	remote *[StrataCount][StratumCapacity]uint64,
) (uint64, bool, error) {
	estimate, err := EstimateStrata(local, remote)
	// coverage:ignore
	if err != nil {
		if errors.Is(err, ErrBudgetExhausted) {
			return 0, false, nil
		}
		return 0, false, err
	}
	return estimate.Delta, true, nil
}

// DecodeBucketSketches decodes concatenated bucket sketches.
func DecodeBucketSketches(encoded []byte, requests []BucketRequest) (BucketDecodeBatch, error) {
	if err := ValidateBucketRequests(requests); err != nil {
		return BucketDecodeBatch{}, err
	}

	offset := 0
	work := maxFactorWork
	var successful []BucketDecodeSuccess
	var failed []FailedBucket
	for _, request := range requests {
		byteLen, ok := safeMul(request.Capacity, 8)
		// coverage:ignore
		if !ok {
			return BucketDecodeBatch{}, ErrInvalidSketchLength
		}
		end, ok := safeAdd(offset, byteLen)
		if !ok || end > len(encoded) {
			return BucketDecodeBatch{}, ErrInvalidSketchLength
		}
		bytes := encoded[offset:end]
		offset = end

		sketch, err := newSketchFromEncodedBytes(request.Capacity, bytes)
		// coverage:ignore
		if err != nil {
			return BucketDecodeBatch{}, err
		}
		roots, err := decodeAndVerifySketch(sketch, request.Capacity, &work)
		if err != nil {
			// coverage:ignore
			if errors.Is(err, ErrDecodeFailure) || errors.Is(err, ErrBudgetExhausted) {
				failed = append(failed, FailedBucket{Depth: request.Depth, Prefix: request.Prefix})
				continue
			}
			// coverage:ignore
			return BucketDecodeBatch{}, err
		}
		successful = append(successful, BucketDecodeSuccess{
			Depth:  request.Depth,
			Prefix: request.Prefix,
			Roots:  roots,
		})
	}

	if offset != len(encoded) {
		return BucketDecodeBatch{}, ErrInvalidSketchLength
	}
	return BucketDecodeBatch{SuccessfulBuckets: successful, FailedBuckets: failed}, nil
}

func safeMul(a, b int) (int, bool) {
	if a == 0 || b == 0 {
		return 0, true
	}
	if a > maxInt/b {
		return 0, false
	}
	return a * b, true
}

func safeAdd(a, b int) (int, bool) {
	if b > maxInt-a {
		return 0, false
	}
	return a + b, true
}

const maxInt = int(^uint(0) >> 1)
