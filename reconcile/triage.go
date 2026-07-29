package reconcile

// MaxBucketedSketchCapacity is the maximum sum of capacities in one bucketed sketch request.
const MaxBucketedSketchCapacity = 4096

// MaxBucketSketchCapacity is the maximum extraction capacity assigned to one bucket.
const MaxBucketSketchCapacity = 32

// BucketRequest describes one localized sketch request.
type BucketRequest struct {
	Depth    uint8
	Prefix   uint32
	Capacity int
}

// BucketDecodeSuccess captures one independently decoded bucket.
type BucketDecodeSuccess struct {
	Depth  uint8
	Prefix uint32
	Roots  []uint64
}

// FailedBucket records a bucket that exceeded decode capacity.
type FailedBucket struct {
	Depth  uint8
	Prefix uint32
}

// BucketDecodeBatch is the partial result of concatenated bucket decoding.
type BucketDecodeBatch struct {
	SuccessfulBuckets []BucketDecodeSuccess
	FailedBuckets     []FailedBucket
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
	var decodedTail uint64
	lowestDecoded := -1

	for stratum := StrataCount - 1; stratum >= 0; stratum-- {
		var residual [StratumCapacity]uint64
		for i := 0; i < StratumCapacity; i++ {
			residual[i] = local[stratum][i] ^ remote[stratum][i]
		}
		roots, err := decodePinSketch(residual[:], StratumCapacity)
		if err != nil {
			// coverage:ignore
			if err == ErrDecodeFailure {
				break
			}
			// coverage:ignore
			return 0, false, err
		}
		cardinality := uint64(len(roots))
		// coverage:ignore
		if decodedTail > ^uint64(0)-cardinality {
			return 0, false, ErrCountOverflow
		}
		decodedTail += cardinality
		lowestDecoded = stratum
	}

	// coverage:ignore
	if lowestDecoded < 0 {
		return 0, false, nil
	}

	// coverage:ignore
	if decodedTail == 0 && lowestDecoded != 0 {
		return 0, false, nil
	}

	shift := uint(lowestDecoded)
	// coverage:ignore
	if shift >= 64 {
		return ^uint64(0), true, nil
	}
	return decodedTail << shift, true, nil
}

// DecodeBucketSketches decodes concatenated bucket sketches.
func DecodeBucketSketches(encoded []byte, requests []BucketRequest) (BucketDecodeBatch, error) {
	if err := ValidateBucketRequests(requests); err != nil {
		return BucketDecodeBatch{}, err
	}

	offset := 0
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

		coordinates := make([]uint64, request.Capacity)
		for i := 0; i < request.Capacity; i++ {
			coordinates[i] = uint64(bytes[i*8]) |
				uint64(bytes[i*8+1])<<8 |
				uint64(bytes[i*8+2])<<16 |
				uint64(bytes[i*8+3])<<24 |
				uint64(bytes[i*8+4])<<32 |
				uint64(bytes[i*8+5])<<40 |
				uint64(bytes[i*8+6])<<48 |
				uint64(bytes[i*8+7])<<56
		}
		sketch, err := NewSyndromeSketchFromCoordinates(coordinates)
		// coverage:ignore
		if err != nil {
			return BucketDecodeBatch{}, err
		}
		roots, err := sketch.DecodeElements(request.Capacity)
		if err != nil {
			// coverage:ignore
			if err == ErrDecodeFailure {
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
