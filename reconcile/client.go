package reconcile

// MaxReconciliationRounds is the baseline policy limit for maximum reconciliation rounds in a single exchange.
const MaxReconciliationRounds = 20

// ReconciliationClient holds requester policy for one exchange.
type ReconciliationClient struct {
	maxSketchCapacity int
	maxRounds         int
	gateThreshold     *uint64
}

// MaxNoProgressRounds bounds repeated stalled split rounds in which every
// split child fails while its sibling also fails, and no bucket resolves a
// nonzero root. It limits grinding attacks without a wire protocol change.
// A round only counts toward the bound when it contains at least one failed
// bucket whose split sibling was also requested; solo capacity retries and
// first-round requests neither confirm nor deny a stall, matching rezzy's
// BucketExchange::advance.
const MaxNoProgressRounds = 3

// BucketExchange carries retry progress across bucket batches. Callers should
// use it instead of repeatedly invoking TransitionBucketBatch directly.
type BucketExchange struct {
	client     ReconciliationClient
	noProgress int
}

// NewBucketExchange starts a bounded retry planner for a reconciliation client.
func (c ReconciliationClient) NewBucketExchange() *BucketExchange {
	return &BucketExchange{client: c}
}

// Advance applies one decoded batch and enforces the no-progress circuit breaker.
// On the breaker it returns ActionPrefixFallback carrying the failed prefixes
// plus the accumulated roots, including this round's successful roots, so
// partial progress is preserved.
func (x *BucketExchange) Advance(batch BucketDecodeBatch, previousRequests []BucketRequest, accumulatedRoots []uint64, globalEstimate *uint64, exchangeRound int, aggregateCap int) ClientAction {
	if stalledSplitRound(batch, previousRequests) {
		x.noProgress++
	} else {
		x.noProgress = 0
	}
	if x.noProgress >= MaxNoProgressRounds {
		merged := append([]uint64(nil), accumulatedRoots...)
		for _, success := range batch.SuccessfulBuckets {
			merged = append(merged, success.Roots...)
		}
		return ClientAction{
			Type:             ActionPrefixFallback,
			Prefixes:         append([]FailedBucket(nil), batch.FailedBuckets...),
			AccumulatedRoots: merged,
		}
	}
	return x.client.TransitionBucketBatch(batch, previousRequests, accumulatedRoots, globalEstimate, exchangeRound, aggregateCap)
}

// stalledSplitRound reports whether a round is a pure stall: every failed
// bucket whose split sibling was also requested has that sibling failing too,
// no such sibling succeeded, and no successful bucket resolved a nonzero root.
// Failed buckets without a requested sibling (solo capacity retries or
// first-round requests) neither confirm nor deny a stall; if the round has no
// split-child failure at all, it is not a stall.
func stalledSplitRound(batch BucketDecodeBatch, previousRequests []BucketRequest) bool {
	anyNonemptySuccess := false
	for _, success := range batch.SuccessfulBuckets {
		if len(success.Roots) > 0 {
			anyNonemptySuccess = true
			break
		}
	}
	sawSplitFailure := false
	allSplitFailuresStalled := true
	for _, failed := range batch.FailedBuckets {
		sibling := failed.Prefix ^ 1
		siblingRequested := false
		for _, request := range previousRequests {
			if request.Depth == failed.Depth && request.Prefix == sibling {
				siblingRequested = true
				break
			}
		}
		if !siblingRequested {
			continue
		}
		sawSplitFailure = true
		for _, success := range batch.SuccessfulBuckets {
			if success.Depth == failed.Depth && success.Prefix == sibling {
				allSplitFailuresStalled = false
			}
		}
	}
	return sawSplitFailure && allSplitFailuresStalled && !anyNonemptySuccess
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
	if maxSketchCapacity <= 0 || maxSketchCapacity > MaxLocalSketchDecodeCapacity {
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
	// ActionPrefixFallback asks the caller to reconcile only the listed failed prefixes.
	ActionPrefixFallback
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
	// Prefixes identifies failed regions for ActionPrefixFallback.
	Prefixes []FailedBucket
}

// SelectAction decides the next protocol step from local and remote state.
// It selects extremity diff for a frame mismatch or unknown remote extremity,
// then checks for matching digests and counts to report synchronization.
// A saturated estimate or an estimator that exhausts its bounded work budget
// selects one depth-0 bucket sketch at the protocol capacity: the h64 tree
// splits any oversized bucket without trusting the estimate, so estimator
// failure alone does not force an extremity transfer. A delta above the
// configured gate still selects extremity diff; remaining cases request
// bucket sketches sized from the estimate. The delta is at least the absolute
// count difference. Low-confidence estimates remain usable. Positive
// concurrencyHeadroom adds event capacity before bucket limits are applied;
// nonpositive values are ignored.
func (c ReconciliationClient) SelectAction(local *ResidentKernel, remote RemoteDigest, concurrencyHeadroom int) ClientAction {
	if !remote.FrameMatches || remote.HasUnknownExtremity {
		return ClientAction{Type: ActionExtremityDiff}
	}
	if local.accumulator.Digest == remote.Digest && local.accumulator.Count == remote.KnownEventCount {
		return ClientAction{Type: ActionSynchronized}
	}

	countDelta := absDiffU64(local.accumulator.Count, remote.KnownEventCount)
	estimate, err := EstimateStrata(local.Strata(), &remote.Strata)
	if err != nil {
		// The estimator exhausted its work budget, so it cannot size a
		// first-round sketch safely. Start with bounded root extraction and
		// let bucket decoding localize any over-capacity region.
		return ClientAction{Type: ActionBucketSketches, Requests: []BucketRequest{{Depth: 0, Prefix: 0, Capacity: MaxBucketSketchCapacity}}}
	}
	estimatedDelta := maxU64(estimate.Delta, countDelta)
	if estimatedDelta >= SaturatedDeltaEstimate {
		// A saturated estimate says only that the difference is too large for
		// the strata sketch. Start at the root with the largest normal bucket
		// sketch and let the ordinary split/retry path localize any overflow.
		return ClientAction{Type: ActionBucketSketches, Requests: []BucketRequest{{Depth: 0, Prefix: 0, Capacity: MaxBucketSketchCapacity}}}
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
	if capacity <= 0 || capacity > c.maxSketchCapacity {
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
		return prefixFallback(batch.FailedBuckets, accumulatedRoots)
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
			// A failed bucket without a prior request cannot be retried or
			// split; hand the caller the failed region instead of bailing the
			// whole exchange, matching rezzy's ladder-failed localization.
			return prefixFallback(batch.FailedBuckets, accumulatedRoots)
		}

		bucketLimit := MaxBucketSketchCapacity
		if previous.Overflow {
			bucketLimit = MaxOverflowBucketCapacity
		}
		if previous.Capacity < bucketLimit {
			floor := previous.Capacity + 1
			target := maxU64(share, uint64(floor))
			capacity, ok := provisionBucketCapacityLimit(target, floor, bucketLimit)
			if !ok {
				return prefixFallback(batch.FailedBuckets, accumulatedRoots)
			}
			total += capacity
			if total > aggregateLimit {
				return prefixFallback(batch.FailedBuckets, accumulatedRoots)
			}
			requests = append(requests, BucketRequest{
				Depth:    previous.Depth,
				Prefix:   failed.Prefix,
				Capacity: capacity,
				Overflow: previous.Overflow,
			})
			continue
		}

		if previous.Depth >= 32 {
			return prefixFallback(batch.FailedBuckets, accumulatedRoots)
		}
		target := maxU64(share/2, 4)
		capacity, ok := provisionBucketCapacityLimit(target, 4, MaxBucketSketchCapacity)
		if !ok {
			return prefixFallback(batch.FailedBuckets, accumulatedRoots)
		}
		nextDepth := previous.Depth + 1
		for sub := 0; sub < 2; sub++ {
			total += capacity
			if total > aggregateLimit {
				return prefixFallback(batch.FailedBuckets, accumulatedRoots)
			}
			requests = append(requests, BucketRequest{
				Depth:    nextDepth,
				Prefix:   (previous.Prefix << 1) | uint32(sub),
				Capacity: capacity,
				Overflow: previous.Overflow,
			})
		}
	}

	return ClientAction{
		Type:             ActionBucketSketches,
		Requests:         requests,
		AccumulatedRoots: accumulatedRoots,
	}
}

func prefixFallback(prefixes []FailedBucket, roots []uint64) ClientAction {
	return ClientAction{
		Type:             ActionPrefixFallback,
		Prefixes:         append([]FailedBucket(nil), prefixes...),
		AccumulatedRoots: append([]uint64(nil), roots...),
	}
}

// NodeSummary is the exact count and h128 XOR for one tree node.
type NodeSummary struct {
	Count  uint64
	Digest [16]byte
}

// VerifySplitConsistency confirms that two child summaries reconstruct their
// parent. A count overflow is treated as inconsistency.
func VerifySplitConsistency(parent, left, right NodeSummary) bool {
	if left.Count > ^uint64(0)-right.Count || parent.Count != left.Count+right.Count {
		return false
	}
	for i := range parent.Digest {
		if parent.Digest[i] != left.Digest[i]^right.Digest[i] {
			return false
		}
	}
	return true
}

// VerifyDecodedNode performs the exact-summary phase of bucket verification.
// Every record whose H64 is in candidates contributes, so H64 collisions are
// handled as a multi-valued mapping. expectedLocal and expectedRemote should
// be the responder/requester summaries advertised for this node.
func VerifyDecodedNode(expectedLocal, expectedRemote NodeSummary, candidates []uint64, local, remote []ElementHash) bool {
	selected := make(map[uint64]struct{}, len(candidates))
	for _, candidate := range candidates {
		if candidate == 0 {
			return false
		}
		if _, duplicate := selected[candidate]; duplicate {
			return false
		}
		selected[candidate] = struct{}{}
	}
	return summarizeCandidates(selected, local) == expectedLocal && summarizeCandidates(selected, remote) == expectedRemote
}

func summarizeCandidates(candidates map[uint64]struct{}, population []ElementHash) NodeSummary {
	var summary NodeSummary
	for _, hash := range population {
		if _, ok := candidates[hash.H64]; !ok {
			continue
		}
		if summary.Count == ^uint64(0) {
			return NodeSummary{Count: ^uint64(0)}
		}
		summary.Count++
		for i := range summary.Digest {
			summary.Digest[i] ^= hash.H128[i]
		}
	}
	return summary
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
	value := estimatedDelta
	half := estimatedDelta / 2
	if value > ^uint64(0)-half {
		return -1
	}
	value += half
	remainder := estimatedDelta % 2
	if value > ^uint64(0)-remainder {
		return -1
	}
	value += remainder
	if value > ^uint64(0)-4 {
		return -1
	}
	value += 4
	if headroom > 0 {
		if headroom > maxInt {
			return -1
		}
		headroomValue := uint64(headroom)
		if value > ^uint64(0)-headroomValue {
			return -1
		}
		value += headroomValue
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
	return provisionBucketCapacityLimit(target, floor, MaxBucketSketchCapacity)
}

func provisionBucketCapacityLimit(target uint64, floor, capacityLimit int) (int, bool) {
	value := target
	half := target / 2
	if value > ^uint64(0)-half {
		return 0, false
	}
	value += half
	remainder := target % 2
	if value > ^uint64(0)-remainder {
		return 0, false
	}
	value += remainder
	if value > ^uint64(0)-4 {
		return 0, false
	}
	value += 4
	if value > uint64(maxInt) {
		return 0, false
	}
	capacity := int(value)
	if capacity < floor {
		capacity = floor
	}
	if capacity > capacityLimit {
		capacity = capacityLimit
	}
	return capacity, true
}
