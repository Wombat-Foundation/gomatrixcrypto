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

// EstimateDelta estimates the symmetric difference from the resident strata.
func EstimateDelta(
	local *[StrataCount][StratumCapacity]uint64,
	remote *[StrataCount][StratumCapacity]uint64,
) (uint64, bool, error) {
	const fallbackEstimate = uint64(8) << 31
	work := maxFactorWork

	for stratum := StrataCount - 1; stratum >= 0; stratum-- {
		var residual [StratumCapacity]uint64
		for i := 0; i < StratumCapacity; i++ {
			residual[i] = local[stratum][i] ^ remote[stratum][i]
		}
		roots, err := decodePinSketch(residual[:], StratumCapacity, &work)
		if err != nil {
			// coverage:ignore
			if errors.Is(err, ErrBudgetExhausted) {
				return 0, false, nil
			}
			// coverage:ignore
			if errors.Is(err, ErrDecodeFailure) {
				return fallbackEstimate, true, nil
			}
			return 0, false, err
		}
		cardinality := uint64(len(roots))
		if cardinality == 0 {
			continue
		}
		if stratum == 31 {
			if cardinality > ^uint64(0)>>31 {
				return fallbackEstimate, true, nil
			}
			return cardinality << 31, true, nil
		}
		shift := uint(stratum + 1)
		if cardinality > ^uint64(0)>>shift {
			return fallbackEstimate, true, nil
		}
		return cardinality << shift, true, nil
	}
	return 0, true, nil
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
		roots, err := decodePinSketch(sketch.Coordinates, request.Capacity, &work)
		if err != nil {
			// coverage:ignore
			if errors.Is(err, ErrDecodeFailure) || errors.Is(err, ErrBudgetExhausted) {
				failed = append(failed, FailedBucket{Depth: request.Depth, Prefix: request.Prefix})
				continue
			}
			// coverage:ignore
			return BucketDecodeBatch{}, err
		}
		// coverage:ignore
		if containsZero(roots) {
			failed = append(failed, FailedBucket{Depth: request.Depth, Prefix: request.Prefix})
			continue
		}
		check, err := NewSyndromeSketch(request.Capacity)
		// coverage:ignore
		if err != nil {
			return BucketDecodeBatch{}, err
		}
		for _, element := range roots {
			// coverage:ignore
			if err := check.Toggle(element); err != nil {
				return BucketDecodeBatch{}, err
			}
		}
		// coverage:ignore
		if !equalSketch(check, sketch) {
			failed = append(failed, FailedBucket{Depth: request.Depth, Prefix: request.Prefix})
			continue
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
