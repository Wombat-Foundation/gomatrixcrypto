//go:build amd64 && !purego

#include "textflag.h"

// func aes256CtrExpandAsm(rk *byte, ctr *byte, out *byte, nblocks int)
//
// out[i] = AES-256(rk, ctr[i]) for i in [0, nblocks).
// Requires AES-NI (AESENC/AESENCLAST); everything else is SSE2/integer.
//
// rk is the 15-key schedule in big-endian byte order, so each round key is a
// fixed 16-byte slot: rk0 at 0, rk1 at 16, ... rk14 at 224.
TEXT ·aes256CtrExpandAsm(SB), NOSPLIT, $0-32
	MOVQ rk+0(FP), BX
	MOVQ ctr+8(FP), SI
	MOVQ out+16(FP), DX
	MOVQ nblocks+24(FP), CX

Lblock:
	MOVUPS (SI), X0
	// PXOR with a memory operand needs a 16-byte-aligned address, and Go
	// hands us a stack array whose alignment it does not promise, so route
	// every round key through MOVUPS.
	MOVUPS (BX), X2
	PXOR   X2, X0
	MOVUPS     16(BX), X1
	AESENC     X1, X0
	MOVUPS     32(BX), X1
	AESENC     X1, X0
	MOVUPS     48(BX), X1
	AESENC     X1, X0
	MOVUPS     64(BX), X1
	AESENC     X1, X0
	MOVUPS     80(BX), X1
	AESENC     X1, X0
	MOVUPS     96(BX), X1
	AESENC     X1, X0
	MOVUPS     112(BX), X1
	AESENC     X1, X0
	MOVUPS     128(BX), X1
	AESENC     X1, X0
	MOVUPS     144(BX), X1
	AESENC     X1, X0
	MOVUPS     160(BX), X1
	AESENC     X1, X0
	MOVUPS     176(BX), X1
	AESENC     X1, X0
	MOVUPS     192(BX), X1
	AESENC     X1, X0
	MOVUPS     208(BX), X1
	AESENC     X1, X0
	MOVUPS     224(BX), X1
	AESENCLAST X1, X0
	MOVUPS     X0, (DX)

	ADDQ $16, SI
	ADDQ $16, DX
	DECQ CX
	JNZ  Lblock
	RET
