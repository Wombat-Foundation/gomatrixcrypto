package keyid

import (
	"encoding/base64"
	"encoding/hex"
	"testing"
)

func TestSHA256AndShortID(t *testing.T) {
	pub, err := base64.RawStdEncoding.DecodeString("CUMlDwB0VzdvaT1nEeaTr21DtluYBSy6dktakGJh1K6o/yrYfthHeoRcG1gCURulT9CUkULCZYQvt2SM20hlAVUB7ehqZjN5fpAFoCtera1xaV8PdqnkbRJwXdtUQf770KVQWPjL9Z4ZwVVyVRpC1P41SehABNsDII0eBcJK65yGHKvnVL+RGBS15oG2oNjQazrWx1S6PZkAVMtq1RIoYJcsAeq6tMOvAW8ML3DXpw2mkYQZKYyxIHBOeDULD1dyO/FAQIRYpdsQumjBHCqiypHdSDu1GLOajB9hxNmAaepGnzWyK24RYgn4p+vd4WI6uhnHlJRJQqq6iOwoD38mIZtHqUIsbAn1xJrkAlRQEHUObZ4O5RNuhRIvuSBa5290pigmdeXhwY+VBjCrJ/mrBS5SOE+njyKqc7fVAYntsGoCrA2AVsOqMwCQpoi7tbLP3lBOzbhFLsWnWJTUkpT5MOqPAWvaSp5+5YEIJiRHteTjm8iVsIF4UWDJ7pNk5HaTCXaoslCgq0cZS4JLGXWS60I2RPL5nzaY/obiT543b5H+CdXXKjUgn0rrwRd+ndzpDpABfu4QMvda/jTV9/TJDZmy/ojyBdUPX1J9sruaTl2pkTkwL11asfrGoRSZt77Cl8FqcgOoXcJEGAeE8SUSmOkdICTVEWesNm9CVJUTJxVOttDjLM4Mvd6SyA/sO1KufVlLIwlH4Z7gH6KPPtJnwsEbSaB0OuWbTntY6K4xTghWvr62Md2TkqQ0CzsTS5y/LqHDcayOc85dcA6ENKMiLLb25cEXegc3uSSegmgKISdfzjeEt1ffK/JGLO16a1luUth6Al5Kv0pRuHXf7uKMWFF3jQQ+ojVyU0dhnD6kvlE8IL5zuYoIFqBAT8ruIw1scmmo+YjK4dJhtWXjOgd8JoHYiJ9GFYkJu3n266KjzQioHQTAPCZzNEFq62hkVSvDWnYJsD5QWRJIKzjLadUYmF0pOUUoq46rQMJi6EiyI6KoNuHj461IbUp726whYgOlZ61xmsgGsFpWDZby/iHN0CVhTQTQROz7fA415ozfIUEi8EU2GkwJcY40mG7ORfF7ixnUzIeC56RSmKtvAnK1n9fDB6CEAAkP7GDlMlRm7UVUnXpHr5jKqOlxMkbcvLytN8sdE/8+WGKwBYhkq13XdNhayVl9W1Ko3m9BxoF5pQZq")
	if err != nil {
		t.Fatal(err)
	}

	sum := SHA256(pub)
	const wantHex = "20fd21bc319285ffbbd0fc54ba6c8581d952ac62e671e90f4184a8b425d2db38"
	if got := hex.EncodeToString(sum[:]); got != wantHex {
		t.Fatalf("digest mismatch: got %s want %s", got, wantHex)
	}
	const wantShort = "IP0hvDGShf-70PxU"
	if got := ShortID(pub); got != wantShort {
		t.Fatalf("short id mismatch: got %s want %s", got, wantShort)
	}
}
