package main

import "testing"

func TestValidateMintingNonceRange(t *testing.T) {
	for _, tc := range []struct {
		name        string
		start, stop uint64
		valid       bool
	}{
		{name: "ordinary range", start: 0, stop: 1024, valid: true},
		{name: "last nonce", start: maxProtocolMintingNonce, stop: maxProtocolMintingNonce + 1, valid: true},
		{name: "start overflows protocol", start: maxProtocolMintingNonce + 1, stop: maxProtocolMintingNonce + 1, valid: false},
		{name: "exclusive end overflows protocol", start: 0, stop: maxProtocolMintingNonce + 2},
	} {
		t.Run(tc.name, func(t *testing.T) {
			err := validateMintingNonceRange(tc.start, tc.stop)
			if (err == nil) != tc.valid {
				t.Fatalf("validateMintingNonceRange(%d, %d) error = %v, valid = %v", tc.start, tc.stop, err, tc.valid)
			}
		})
	}
}
