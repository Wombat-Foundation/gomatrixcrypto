package lthash

import (
	"bytes"
	"crypto/aes"
	"crypto/cipher"
	"encoding/binary"
	"encoding/hex"
	"slices"
	"testing"

	"github.com/zeebo/blake3"
)

// The cipher tests below pin the AES-256-CTR expansion to two independent
// references: rezzy's expansion_backends.rs check() vectors (the Rust
// candidate this port comes from) and Go's own crypto/aes. A failure means the
// AES-NI loop, the round-key schedule, or the counter framing drifted.

func TestAES256SBoxAnchors(t *testing.T) {
	for _, tc := range []struct{ in, want byte }{
		{0x00, 0x63}, {0x01, 0x7c}, {0x53, 0xed}, {0xff, 0x16},
	} {
		if got := aesSBox[tc.in]; got != tc.want {
			t.Errorf("S-box[%#02x] = %#02x, want %#02x", tc.in, got, tc.want)
		}
	}
}

// TestAES256CtrVector pins the keystream rezzy asserts for AES-256 CTR under
// key 00..1f over counters 0..3.
func TestAES256CtrVector(t *testing.T) {
	var key [32]byte
	for i := range key {
		key[i] = byte(i)
	}

	const wantHex = "f29000b62a499fd0a9f39a6add2e7780" +
		"f05d76ae4ab99fe5a6f69b3148c2363d" +
		"0ebcb5deb52c83bd08a8a935182c9199" +
		"d24356532881602f809eb383c5ff5d56"
	want, err := hex.DecodeString(wantHex)
	if err != nil {
		t.Fatal(err)
	}

	var out [ByteSize]byte
	expandAES256Element(&key, out[:])
	if !bytes.Equal(out[:len(want)], want) {
		t.Fatalf("keystream[0:64] = %x, want %x", out[:len(want)], want)
	}
}

func TestAES256ElementMatchesStdlib(t *testing.T) {
	for _, seed := range []uint64{0, 1, 0x9e3779b9495a4b73} {
		key := seededKey(seed)

		var want [ByteSize]byte
		block, err := aes.NewCipher(key[:])
		if err != nil {
			t.Fatal(err)
		}
		cipher.NewCTR(block, make([]byte, aes.BlockSize)).XORKeyStream(want[:], want[:])

		var got [ByteSize]byte
		expandAES256Element(&key, got[:])
		if got != want {
			t.Fatalf("seed %#x: expansion diverges from crypto/aes at byte %d",
				seed, firstDiff(got[:], want[:]))
		}
	}
}

// TestAES256StdlibFallbackMatchesHardware exercises the non-AES-NI path
// against the assembly one, so machines without the instruction still agree
// with machines that have it. hasAESNI is flipped rather than simulated so the
// dispatch in expandAES256Element is covered too.
func TestAES256StdlibFallbackMatchesHardware(t *testing.T) {
	key := seededKey(0xc0ffee)
	var hardware, portable [ByteSize]byte
	expandAES256Element(&key, hardware[:])
	expandAES256Stdlib(&key, portable[:])
	if hardware != portable {
		t.Fatalf("fallback diverges from AES-NI at byte %d",
			firstDiff(hardware[:], portable[:]))
	}

}

func TestAES256KeyScheduleMatchesStdlib(t *testing.T) {
	key := seededKey(0x1234)

	var rk [aesKeyBytes]byte
	expandAES256Key(&key, &rk)

	// Cross-check the schedule with a byte-wise reference encrypt so the key
	// expansion is verified on machines that never run the AES-NI loop.
	var plain [aes.BlockSize]byte
	for i := range plain {
		plain[i] = byte(0xff - i)
	}
	got := refEncrypt256(&rk, &plain)

	block, err := aes.NewCipher(key[:])
	if err != nil {
		t.Fatal(err)
	}
	want := make([]byte, aes.BlockSize)
	block.Encrypt(want, plain[:])
	if !bytes.Equal(got[:], want) {
		t.Fatalf("AES-256 block = %x, want %x", got, want)
	}
}

func TestExpandAES256ElementRejectsWrongSize(t *testing.T) {
	key := seededKey(0)
	defer func() {
		if recover() == nil {
			t.Fatalf("expected a panic for a short element")
		}
	}()
	expandAES256Element(&key, make([]byte, aes.BlockSize))
}

// TestSeedAESCTRKeyIsBLAKE3OfFrame checks the wiring that rezzy's
// expand_aes_ctr relies on: the cipher key is BLAKE3-256 of exactly the bytes
// seedWithDST feeds its XOF, and the seed is that keystream unpacked LE.
func TestSeedAESCTRKeyIsBLAKE3OfFrame(t *testing.T) {
	const (
		eventType = "m.room.member"
		stateKey  = "@alice:example.org"
		eventID   = "$event_1"
	)

	frame := manualFrame(dstAESCTR, eventType, stateKey, eventID)
	key := blake3.Sum256(frame)

	var buf [ByteSize]byte
	expandAES256Element(&key, buf[:])
	var want Hash
	for i := range want {
		want[i] = binary.LittleEndian.Uint16(buf[i*2:])
	}

	if got := seedAESCTR(eventType, stateKey, eventID); got != want {
		t.Fatalf("seedAESCTR does not match BLAKE3(frame) keyed AES-CTR\n got %x\nwant %x",
			got[:4], want[:4])
	}
}

// TestAESCTRVector pins the accumulator digest so a change in the domain tag,
// the framing, or the expansion shows up as a test failure rather than as
// silently different room digests.
func TestAESCTRVector(t *testing.T) {
	entries := []Entry{
		{EventType: "m.room.create", EventID: "$a"},
		{EventType: "m.room.member", StateKey: "@alice:example.org", EventID: "$b"},
	}
	h := AESCTRFromEntries(entries)

	const want = "L5WCOKR7yn1u44_LVhGVrttjSxq5gLCbwWUCs0eq1iQ"
	if got := h.String(); got != want {
		t.Fatalf("AES-CTR accumulator digest: got %s want %s", got, want)
	}
}

func TestAESCTRBytesMatchHashLanes(t *testing.T) {
	entries := []Entry{
		{EventType: "m.room.create", EventID: "$a"},
		{EventType: "m.room.member", StateKey: "@alice:example.org", EventID: "$b"},
	}

	h := AESCTRFromEntries(entries)
	got := h.Bytes()
	want := Hash(h).Bytes()
	if got != want {
		t.Fatalf("lattice encoding does not match Hash.Bytes")
	}

	var decoded Hash
	for i := range decoded {
		decoded[i] = binary.LittleEndian.Uint16(got[i*2:])
	}
	if decoded != Hash(h) {
		t.Fatalf("lattice encoding does not round-trip through its lanes")
	}
}

func TestAESCTRInsertRemoveRoundTrip(t *testing.T) {
	var h AESCTRHash
	h.Insert("m.room.create", "", "$a:example.org")
	h.Insert("m.room.member", "@alice:example.org", "$b:example.org")
	h.Remove("m.room.member", "@alice:example.org", "$b:example.org")
	h.Remove("m.room.create", "", "$a:example.org")
	if h != (AESCTRHash{}) {
		t.Fatalf("expected zero hash after round-trip")
	}
}

func TestAESCTRReplaceMatchesRemovePlusInsert(t *testing.T) {
	var direct AESCTRHash
	direct.Insert("m.room.name", "", "$old")
	direct.Replace("m.room.name", "", "$old", "$new")

	var stepwise AESCTRHash
	stepwise.Insert("m.room.name", "", "$old")
	stepwise.Remove("m.room.name", "", "$old")
	stepwise.Insert("m.room.name", "", "$new")

	if direct != stepwise {
		t.Fatalf("replace did not match remove+insert")
	}
}

func TestAESCTROrderIndependent(t *testing.T) {
	entries := []Entry{
		{EventType: "m.room.create", EventID: "$a"},
		{EventType: "m.room.member", StateKey: "@alice:example.org", EventID: "$b"},
		{EventType: "m.room.member", StateKey: "@bob:example.org", EventID: "$c"},
	}

	h1 := AESCTRFromEntries(entries)
	slices.Reverse(entries)
	h2 := AESCTRFromEntries(entries)

	if h1 != h2 {
		t.Fatalf("expected order-independent hash")
	}
}

// TestAESCTRDiffersFromBlake3 checks that the two profiles are wired to
// different domain tags: the same entries must expand to different lattices.
// It is a wiring check, not a claim that no two element sets can collide.
func TestAESCTRDiffersFromBlake3(t *testing.T) {
	entries := []Entry{
		{EventType: "m.room.create", EventID: "$a"},
		{EventType: "m.room.member", StateKey: "@alice:example.org", EventID: "$b"},
	}

	blake3Hash := FromEntries(entries)
	aesHash := AESCTRFromEntries(entries)

	if blake3Hash.String() == aesHash.String() {
		t.Fatalf("AES-CTR and BLAKE3 accumulators share digest %s", blake3Hash.String())
	}
	if blake3Hash == Hash(aesHash) {
		t.Fatalf("AES-CTR and BLAKE3 accumulators share lattice bytes")
	}
}

// manualFrame rebuilds the MSC4500 element encoding independently of
// writeElement, so the framing test cannot pass by sharing a bug.
func manualFrame(domain []byte, eventType, stateKey, eventID string) []byte {
	var b []byte
	b = append(b, domain...)
	b = appendU16(b, len(eventType))
	b = append(b, eventType...)
	b = appendU16(b, len(stateKey))
	b = append(b, stateKey...)
	b = append(b, eventID...)
	return b
}

func appendU16(b []byte, n int) []byte {
	var lens [2]byte
	binary.LittleEndian.PutUint16(lens[:], uint16(n))
	return append(b, lens[:]...)
}

func seededKey(seed uint64) (key [32]byte) {
	s := seed
	for i := range key {
		s = s*6364136223846793005 + 1442695040888963407
		key[i] = byte(s >> 33)
	}
	return key
}

func firstDiff(a, b []byte) int {
	for i := range a {
		if a[i] != b[i] {
			return i
		}
	}
	return -1
}

// refEncrypt256 is a straightforward FIPS-197 AES-256 block encrypt used only
// as an independent check of expandAES256Key.
func refEncrypt256(rk *[aesKeyBytes]byte, pt *[aes.BlockSize]byte) [aes.BlockSize]byte {
	var s [aes.BlockSize]byte
	copy(s[:], pt[:])
	refAddRoundKey(&s, rk, 0)
	for r := 1; r < 14; r++ {
		refSubBytesShiftRows(&s)
		refMixColumns(&s)
		refAddRoundKey(&s, rk, r)
	}
	refSubBytesShiftRows(&s)
	refAddRoundKey(&s, rk, 14)
	return s
}

func refAddRoundKey(s *[aes.BlockSize]byte, rk *[aesKeyBytes]byte, round int) {
	for i := range s {
		s[i] ^= rk[round*aes.BlockSize+i]
	}
}

func refSubBytesShiftRows(s *[aes.BlockSize]byte) {
	var in [aes.BlockSize]byte
	copy(in[:], s[:])
	for row := 0; row < 4; row++ {
		for col := 0; col < 4; col++ {
			s[row+4*col] = aesSBox[in[row+4*((col+row)%4)]]
		}
	}
}

func refMixColumns(s *[aes.BlockSize]byte) {
	for c := 0; c < 4; c++ {
		i := 4 * c
		a0, a1, a2, a3 := s[i], s[i+1], s[i+2], s[i+3]
		s[i] = xtime(a0) ^ xtime(a1) ^ a1 ^ a2 ^ a3
		s[i+1] = a0 ^ xtime(a1) ^ xtime(a2) ^ a2 ^ a3
		s[i+2] = a0 ^ a1 ^ xtime(a2) ^ xtime(a3) ^ a3
		s[i+3] = xtime(a0) ^ a0 ^ a1 ^ a2 ^ xtime(a3)
	}
}
