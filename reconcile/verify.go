package reconcile

import "math/bits"

// Classified holds one node's decoded roots, classified by local H64 presence.
// Keyed by the node's (Depth, Prefix); VerifyFollowUp refuses a follow-up for
// any other node.
type Classified struct {
	// Depth is the binary-tree depth of the verified node.
	Depth uint8
	// Prefix is the binary prefix at the given depth.
	Prefix uint32
	// LRoots are roots present locally (the remote lacks them), sorted.
	LRoots []uint64
	// MRoots are roots absent locally; their identifiers must come from the peer, sorted.
	MRoots []uint64
	// LocalAccumulated is the XOR of every local H128 candidate under an L root.
	LocalAccumulated [16]byte
	// Local is the requester's summary of this node.
	Local NodeSummary
	// Remote is the responder's summary of this node, as claimed in the exchange.
	Remote NodeSummary
}

// Residual returns D_A xor D_B for this node.
func (c Classified) Residual() [16]byte {
	var residual [16]byte
	for i := range residual {
		residual[i] = c.Local.Digest[i] ^ c.Remote.Digest[i]
	}
	return residual
}

// Population returns the larger side's element count for the node.
func (c Classified) Population() uint64 {
	if c.Local.Count > c.Remote.Count {
		return c.Local.Count
	}
	return c.Remote.Count
}

// VerifyDecode performs phase 1 for one node: classify roots and enforce
// count_A - count_B = |L| - |M|.
//
// local and remote are the two sides' summaries of this node. localCandidates
// returns every local H128 candidate whose H64 is root (the multi-valued map;
// empty means absent). Roots must be distinct and fall inside the node. When
// M is empty the residual is checked immediately, provided no L root is
// ambiguous. Every record whose H64 is a root contributes, so H64 collisions
// are handled as a multi-valued mapping; a caller that presents peer-supplied
// hashes directly instead of deriving them from local state is outside this
// function's contract.
func VerifyDecode(request BucketRequest, local, remote NodeSummary, roots []uint64, localCandidates func(uint64) [][16]byte) (Classified, bool) {
	sorted := append([]uint64(nil), roots...)
	// The decoder yields distinct roots; reject a caller that does not, since
	// a repeated root would be masked by the length check in phase 2.
	for i := 1; i < len(sorted); i++ {
		if sorted[i] == sorted[i-1] {
			return Classified{}, false
		}
	}
	for _, root := range roots {
		if !bucketContains(request.Depth, request.Prefix, root) {
			return Classified{}, false
		}
	}

	var classified Classified
	classified.Depth = request.Depth
	classified.Prefix = request.Prefix
	classified.Local = local
	classified.Remote = remote
	ambiguous := false
	for _, root := range roots {
		candidates := localCandidates(root)
		if len(candidates) == 0 {
			classified.MRoots = append(classified.MRoots, root)
			continue
		}
		if len(candidates) > 1 {
			ambiguous = true
		}
		for _, candidate := range candidates {
			for i := range classified.LocalAccumulated {
				classified.LocalAccumulated[i] ^= candidate[i]
			}
		}
		classified.LRoots = append(classified.LRoots, root)
	}

	// count_A - count_B = |L| - |M|, rearranged as count_A + |M| =
	// count_B + |L| so the check needs no signed widening; carries must
	// agree for the equality to hold in uint64.
	localSum, localCarry := bits.Add64(local.Count, uint64(len(classified.MRoots)), 0)
	remoteSum, remoteCarry := bits.Add64(remote.Count, uint64(len(classified.LRoots)), 0)
	if localCarry != remoteCarry || localSum != remoteSum {
		return Classified{}, false
	}

	if len(classified.MRoots) == 0 && !ambiguous {
		var accumulated [][16]byte
		accumulated = append(accumulated, classified.LocalAccumulated)
		if !VerifyGlobalResidual(classified.Residual(), accumulated, nil) {
			return Classified{}, false
		}
	}
	return classified, true
}

// VerifyFollowUp performs phase 2 for one node: check the identifiers the peer
// returned for M.
//
// returned holds the canonical 32-byte digests D(e) computed locally from the
// returned identifiers. This function derives H64 and H128 itself, so
// peer-supplied hashes can never be passed in. Each must re-derive to a root
// in M, each root in M must be covered exactly once, and the node's full
// residual D_A xor D_B = A(L) xor A(M) must hold. A root with several local
// candidates is resolved here by that residual, or the result is discarded.
// A request for a different node than classified is refused.
func VerifyFollowUp(classified Classified, depth uint8, prefix uint32, returned [][32]byte) bool {
	if classified.Depth != depth || classified.Prefix != prefix || len(returned) != len(classified.MRoots) {
		return false
	}
	covered := make([]bool, len(classified.MRoots))
	var remoteRoots [][16]byte
	for i := range returned {
		hash := FromDigest32(returned[i])
		slot := -1
		for j, root := range classified.MRoots {
			if root == hash.H64 {
				slot = j
				break
			}
		}
		if slot < 0 {
			return false
		}
		if covered[slot] {
			return false
		}
		covered[slot] = true
		remoteRoots = append(remoteRoots, hash.H128)
	}
	// Equal lengths plus no repeat means every root is covered exactly once.
	var localRoots [][16]byte
	localRoots = append(localRoots, classified.LocalAccumulated)
	return VerifyGlobalResidual(classified.Residual(), localRoots, remoteRoots)
}

// bucketContains reports whether root falls inside the (depth, prefix) node:
// the root's leading depth bits must equal prefix. Depth 0 covers everything;
// depths are capped at 32 by ValidateBucketRequests, matching the h64 trie.
func bucketContains(depth uint8, prefix uint32, root uint64) bool {
	if depth == 0 {
		return true
	}
	return uint64(root>>(64-depth)) == uint64(prefix)
}
