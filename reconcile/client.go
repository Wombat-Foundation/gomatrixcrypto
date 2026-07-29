package reconcile

// MaxReconciliationRounds is the baseline policy limit for maximum reconciliation rounds in a single exchange.
const MaxReconciliationRounds = 20

// ReconciliationClient holds requester policy for one exchange.
type ReconciliationClient struct {
	maxSketchCapacity int
	maxRounds         int
	gateThreshold     *uint64
}

func gateThresholdForRounds(maxRounds int) uint64 {
	if maxRounds <= 0 {
		return 0
	}

	rounds := uint64(maxRounds)
	maxThreshold := ^uint64(0) / MaxBucketedSketchCapacity
	if rounds > maxThreshold {
		return ^uint64(0)
	}

	return rounds * MaxBucketedSketchCapacity
}

// NewReconciliationClient creates a requester with an explicit local decode cap.
func NewReconciliationClient(maxSketchCapacity int) (*ReconciliationClient, error) {
	if maxSketchCapacity == 0 || maxSketchCapacity > MaxLocalSketchDecodeCapacity {
		return nil, ErrInvalidSketchCapacity
	}
	threshold := gateThresholdForRounds(MaxReconciliationRounds)
	return &ReconciliationClient{
		maxSketchCapacity: maxSketchCapacity,
		maxRounds:         MaxReconciliationRounds,
		gateThreshold:     &threshold,
	}, nil
}

// WithMaxRounds returns a copy with a custom round limit.
func (c ReconciliationClient) WithMaxRounds(maxRounds int) ReconciliationClient {
	c.maxRounds = maxRounds
	threshold := gateThresholdForRounds(maxRounds)
	c.gateThreshold = &threshold
	return c
}

// WithGateThreshold returns a copy with a custom delta gate.
func (c ReconciliationClient) WithGateThreshold(threshold *uint64) ReconciliationClient {
	c.gateThreshold = threshold
	return c
}

// AllowUnlimitedDelta disables the delta gate.
func (c ReconciliationClient) AllowUnlimitedDelta() ReconciliationClient {
	c.gateThreshold = nil
	return c
}

// MaxRounds returns the round limit.
func (c ReconciliationClient) MaxRounds() int {
	return c.maxRounds
}

// GateThreshold returns the optional delta gate threshold.
func (c ReconciliationClient) GateThreshold() (uint64, bool) {
	if c.gateThreshold == nil {
		return 0, false
	}
	return *c.gateThreshold, true
}

// RemoteDigest captures the responder's room digest and strata.
type RemoteDigest struct {
	// Digest is the responder's 128-bit room accumulator digest.
	Digest [16]byte
	// KnownEventCount is the responder's exact event count.
	KnownEventCount uint64
	// Strata contains the responder's 32-entry strata estimator.
	Strata [StrataCount][StratumCapacity]uint64
	// FrameMatches reports whether the peers negotiated the same frame.
	FrameMatches bool
	// HasUnknownExtremity reports whether the responder has unconfirmed extremity state.
	HasUnknownExtremity bool
}

// ClientActionType selects the next protocol step.
type ClientActionType int

const (
	// ActionSynchronized means both peers are already aligned.
	ActionSynchronized ClientActionType = iota
	// ActionExtremityDiff requests the extremity-diff fallback path.
	ActionExtremityDiff
	// ActionBucketSketches requests localized bucket sketches.
	ActionBucketSketches
	// ActionResolveRoots returns decoded roots to the caller.
	ActionResolveRoots
)

// ClientAction is the next request selected by the reconciliation client.
type ClientAction struct {
	// Type is the selected protocol action.
	Type ClientActionType
	// Requests are the bucket sketch requests to send when Type is ActionBucketSketches.
	Requests []BucketRequest
	// AccumulatedRoots carries previously resolved roots across retries.
	AccumulatedRoots []uint64
	// Roots carries the final resolved roots when Type is ActionResolveRoots.
	Roots []uint64
}

// SelectAction decides the next protocol step from local and remote state.
func (c ReconciliationClient) SelectAction(local *ResidentKernel, remote RemoteDigest, concurrencyHeadroom int) ClientAction {
	if !remote.FrameMatches || remote.HasUnknownExtremity {
		return ClientAction{Type: ActionExtremityDiff}
	}
	if local.accumulator.Digest == remote.Digest && local.accumulator.Count == remote.KnownEventCount {
		return ClientAction{Type: ActionSynchronized}
	}

	countDelta := absDiffU64(local.accumulator.Count, remote.KnownEventCount)
	estimatedDelta := countDelta
	// coverage:ignore
	if value, ok, err := EstimateDelta(local.Strata(), &remote.Strata); err == nil {
		if ok && value > estimatedDelta {
			estimatedDelta = value
		}
	}

	if c.gateThreshold != nil && estimatedDelta > *c.gateThreshold {
		return ClientAction{Type: ActionExtremityDiff}
	}

	provisioned := provisionCapacity(estimatedDelta, concurrencyHeadroom)
	targetCapacity := provisioned
	if targetCapacity < 0 {
		targetCapacity = maxInt
	}

	depth := uint8(0)
	buckets := 1
	for buckets*32 < targetCapacity && depth < 6 {
		depth++
		buckets *= 2
	}

	perBucket := ceilDiv(targetCapacity, buckets)
	if perBucket < 4 {
		perBucket = 4
	}
	if perBucket > MaxBucketSketchCapacity {
		perBucket = MaxBucketSketchCapacity
	}

	requests := make([]BucketRequest, 0, buckets)
	for prefix := 0; prefix < buckets; prefix++ {
		requests = append(requests, BucketRequest{
			Depth:    depth,
			Prefix:   uint32(prefix),
			Capacity: perBucket,
		})
	}

	return ClientAction{
		Type:     ActionBucketSketches,
		Requests: requests,
	}
}

// BuildSketch constructs an unbucketed sketch over the negotiated frame.
func (c ReconciliationClient) BuildSketch(capacity int, hashes []ElementHash) (*SyndromeSketch, error) {
	if capacity == 0 || capacity > c.maxSketchCapacity {
		return nil, ErrInvalidSketchCapacity
	}
	sketch, err := NewSyndromeSketch(capacity)
	// coverage:ignore
	if err != nil {
		return nil, err
	}
	for _, hash := range hashes {
		if err := sketch.Toggle(hash.H64); err != nil {
			return nil, err
		}
	}
	return sketch, nil
}

// TransitionBucketBatch advances the bucket-decoding exchange.
func (c ReconciliationClient) TransitionBucketBatch(
	batch BucketDecodeBatch,
	previousRequests []BucketRequest,
	accumulatedRoots []uint64,
	globalEstimate *uint64,
	exchangeRound int,
	aggregateCap int,
) ClientAction {
	for _, success := range batch.SuccessfulBuckets {
		accumulatedRoots = append(accumulatedRoots, success.Roots...)
	}
	if len(batch.FailedBuckets) == 0 {
		return ClientAction{Type: ActionResolveRoots, Roots: accumulatedRoots}
	}
	if exchangeRound >= c.maxRounds {
		return ClientAction{Type: ActionExtremityDiff}
	}

	resolvedCount := uint64(len(accumulatedRoots))
	unaccounted := uint64(0)
	if globalEstimate != nil && *globalEstimate > resolvedCount {
		unaccounted = *globalEstimate - resolvedCount
	}
	failedCount := uint64(len(batch.FailedBuckets))
	share := unaccounted / failedCount
	aggregateLimit := aggregateCap
	if aggregateLimit > MaxBucketedSketchCapacity {
		aggregateLimit = MaxBucketedSketchCapacity
	}

	total := 0
	requests := make([]BucketRequest, 0, len(batch.FailedBuckets))
	for _, failed := range batch.FailedBuckets {
		var previous *BucketRequest
		for i := range previousRequests {
			if previousRequests[i].Prefix == failed.Prefix && previousRequests[i].Depth == failed.Depth {
				previous = &previousRequests[i]
				break
			}
		}
		if previous == nil {
			return ClientAction{Type: ActionExtremityDiff}
		}

		if previous.Capacity < MaxBucketSketchCapacity {
			floor := previous.Capacity + 1
			target := maxU64(share, uint64(floor))
			capacity, ok := provisionBucketCapacity(target, floor)
			if !ok {
				return ClientAction{Type: ActionExtremityDiff}
			}
			total += capacity
			if total > aggregateLimit {
				return ClientAction{Type: ActionExtremityDiff}
			}
			requests = append(requests, BucketRequest{
				Depth:    previous.Depth,
				Prefix:   failed.Prefix,
				Capacity: capacity,
			})
			continue
		}

		if previous.Depth >= 31 {
			return ClientAction{Type: ActionExtremityDiff}
		}
		target := maxU64(share/2, 4)
		capacity, ok := provisionBucketCapacity(target, 4)
		if !ok {
			return ClientAction{Type: ActionExtremityDiff}
		}
		nextDepth := previous.Depth + 1
		for sub := 0; sub < 2; sub++ {
			total += capacity
			if total > aggregateLimit {
				return ClientAction{Type: ActionExtremityDiff}
			}
			requests = append(requests, BucketRequest{
				Depth:    nextDepth,
				Prefix:   (previous.Prefix << 1) | uint32(sub),
				Capacity: capacity,
			})
		}
	}

	return ClientAction{
		Type:             ActionBucketSketches,
		Requests:         requests,
		AccumulatedRoots: accumulatedRoots,
	}
}

// VerifyGlobalResidual checks that the supplied roots reproduce the residual.
func VerifyGlobalResidual(expectedResidual [16]byte, localRoots, remoteRoots [][16]byte) bool {
	var actual [16]byte
	for _, hash := range localRoots {
		for i := range actual {
			actual[i] ^= hash[i]
		}
	}
	for _, hash := range remoteRoots {
		for i := range actual {
			actual[i] ^= hash[i]
		}
	}
	return actual == expectedResidual
}

func absDiffU64(a, b uint64) uint64 {
	if a >= b {
		return a - b
	}
	return b - a
}

func provisionCapacity(estimatedDelta uint64, headroom int) int {
	value := estimatedDelta + estimatedDelta/2 + estimatedDelta%2 + 4
	if headroom > 0 {
		value += uint64(headroom)
	}
	if value > uint64(maxInt) {
		return -1
	}
	return int(value)
}

func ceilDiv(n, d int) int {
	if d <= 0 {
		return 0
	}
	if n <= 0 {
		return 0
	}
	q := n / d
	if n%d != 0 {
		q++
	}
	return q
}

func maxU64(a, b uint64) uint64 {
	if a > b {
		return a
	}
	return b
}

func provisionBucketCapacity(target uint64, floor int) (int, bool) {
	value := target + target/2 + target%2 + 4
	if value > uint64(maxInt) {
		return 0, false
	}
	capacity := int(value)
	if capacity < floor {
		capacity = floor
	}
	if capacity > MaxBucketSketchCapacity {
		capacity = MaxBucketSketchCapacity
	}
	return capacity, true
}
