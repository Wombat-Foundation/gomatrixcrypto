// solve_main.cpp — standalone CLI wrapper around John Tromp's reference
// "mean" (bucket-sort) Cuckoo Cycle solver (external/cuckoo submodule).
//
// This exists so Go can shell out to a prebuilt binary over a plain
// argv-in / stdout-out protocol instead of embedding a cgo/C++ build
// step in `go build` — simpler to test standalone and simpler to wire
// up from Go (os/exec + a couple lines of text parsing).
//
// EDGEBITS/PROOFSIZE/NSIPHASH are compile-time constants in the vendored
// C++ (see cuckoo.h), fixed via -D flags at build time to the one profile
// this is for: EdgeBits=29, ProofSize=42
// (tk.nutra.msc45xx.pow.cuckoo-cycle-42-29-sha3-256-cogen).
//
// We bypass the reference code's own key derivation (setheadernonce,
// which hashes a header with blake2b) entirely: our graph_seed is
// already four little-endian 64-bit words per the MSC, and Tromp's
// siphash_keys treats k0..k3 as the raw SipHash v0..v3 state with no key
// schedule — the same convention our Go siphash24 implementation uses —
// so writing our words directly into sip_keys is bit-for-bit compatible.
//
// Usage: cuckoo_solve_29_42 <k0_hex> <k1_hex> <k2_hex> <k3_hex> [nthreads [ntrims]]
// Output (stdout):
//   line 1: "SOLVED" or "NOSOL"
//   line 2 (only if SOLVED): PROOFSIZE decimal edge nonces, space-separated
#include "mean.hpp"

#include <cstdio>
#include <cstdlib>
#include <thread>

static unsigned long long parseHex(const char *s) {
	return strtoull(s, nullptr, 16);
}

int main(int argc, char **argv) {
	if (argc < 5) {
		fprintf(stderr, "usage: %s <k0_hex> <k1_hex> <k2_hex> <k3_hex> [nthreads [ntrims]]\n", argv[0]);
		return 2;
	}
	unsigned long long k0 = parseHex(argv[1]);
	unsigned long long k1 = parseHex(argv[2]);
	unsigned long long k2 = parseHex(argv[3]);
	unsigned long long k3 = parseHex(argv[4]);

	unsigned int nthreads = argc > 5 ? (unsigned int)atoi(argv[5]) : std::thread::hardware_concurrency();
	if (nthreads == 0) {
		nthreads = 1;
	}
	unsigned int ntrims = argc > 6 ? (unsigned int)atoi(argv[6]) : (EDGEBITS >= 30 ? 96 : 68);

	solver_ctx ctx(nthreads, ntrims, false, true);
	ctx.trimmer->sip_keys.k0 = k0;
	ctx.trimmer->sip_keys.k1 = k1;
	ctx.trimmer->sip_keys.k2 = k2;
	ctx.trimmer->sip_keys.k3 = k3;
	ctx.sols.clear();

	int nsols = ctx.solve();
	if (nsols <= 0) {
		printf("NOSOL\n");
		return 0;
	}

	printf("SOLVED\n");
	for (int i = 0; i < PROOFSIZE; i++) {
		printf(i == 0 ? "%u" : " %u", (unsigned int)ctx.sols[i]);
	}
	printf("\n");
	return 0;
}
