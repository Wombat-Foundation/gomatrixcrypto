//go:build amd64 && !purego

package lthash

import "github.com/klauspost/cpuid/v2"

// aes256CtrExpandAsm encrypts nblocks blocks: out[i] = AES-256(rk, ctr[i]).
//
//go:noescape
func aes256CtrExpandAsm(rk *byte, ctr *byte, out *byte, nblocks int)

// hasAESNI reports whether this CPU can run the AES-NI block loop.
var hasAESNI = cpuid.CPU.Has(cpuid.AESNI)

// aesHardwareExpand runs the AES-NI block loop when the CPU has it. The round
// keys are a stack array; //go:noescape on the assembly keeps them there.
func aesHardwareExpand(key *[32]byte, out []byte) bool {
	if !hasAESNI {
		return false
	}
	var rk [aesKeyBytes]byte
	expandAES256Key(key, &rk)
	aes256CtrExpandAsm(&rk[0], &aesCtrInput[0], &out[0], aesElementBlocks)
	return true
}
