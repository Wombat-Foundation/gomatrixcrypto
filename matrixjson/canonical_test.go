package matrixjson

import (
	"encoding/json"
	"errors"
	"testing"
)

func TestCanonicalSortsKeysAndCompacts(t *testing.T) {
	got, err := Canonical(map[string]any{
		"z": int64(2),
		"a": []any{true, nil, "x"},
		"m": map[string]any{
			"b": "second",
			"a": "first",
		},
	})
	if err != nil {
		t.Fatal(err)
	}
	const want = `{"a":[true,null,"x"],"m":{"a":"first","b":"second"},"z":2}`
	if string(got) != want {
		t.Fatalf("canonical mismatch: got %s want %s", got, want)
	}
}

func TestCanonicalStringEscaping(t *testing.T) {
	got, err := Canonical(map[string]any{
		"html": "<>&",
		"line": "a\nb",
		"nul":  "\x00",
	})
	if err != nil {
		t.Fatal(err)
	}
	const want = `{"html":"<>&","line":"a\nb","nul":"\u0000"}`
	if string(got) != want {
		t.Fatalf("canonical mismatch: got %s want %s", got, want)
	}
}

func TestCanonicalRejectsOutOfRangeIntegersAndFloats(t *testing.T) {
	if _, err := Canonical(map[string]any{"n": int64(1 << 53)}); !errors.Is(err, ErrIntegerRange) {
		t.Fatalf("expected integer range error, got %v", err)
	}
	if _, err := Canonical(map[string]any{"n": json.Number("1.5")}); !errors.Is(err, ErrUnsupportedType) {
		t.Fatalf("expected unsupported number error, got %v", err)
	}
	if _, err := Canonical(map[string]any{"n": 1.5}); !errors.Is(err, ErrUnsupportedType) {
		t.Fatalf("expected unsupported float error, got %v", err)
	}
}

func TestCanonicalRejectsOutOfRangeUint(t *testing.T) {
	if _, err := Canonical(uint64(1) << 63); !errors.Is(err, ErrIntegerRange) {
		t.Fatalf("expected integer range error, got %v", err)
	}
}

func TestCanonicalRejectsNonStringMapKeys(t *testing.T) {
	if _, err := Canonical(map[int]string{1: "x"}); !errors.Is(err, ErrUnsupportedType) {
		t.Fatalf("expected unsupported map key error, got %v", err)
	}
}

func TestCanonicalScalarsPointersAndArrays(t *testing.T) {
	value := "x"
	got, err := Canonical([]any{nil, &value, uint(7), [2]int{1, 2}})
	if err != nil {
		t.Fatal(err)
	}
	const want = `[null,"x",7,[1,2]]`
	if string(got) != want {
		t.Fatalf("canonical mismatch: got %s want %s", got, want)
	}
}

func TestCanonicalJSONNumberInteger(t *testing.T) {
	got, err := Canonical(map[string]any{"n": json.Number("42")})
	if err != nil {
		t.Fatal(err)
	}
	const want = `{"n":42}`
	if string(got) != want {
		t.Fatalf("canonical mismatch: got %s want %s", got, want)
	}
}

func TestCanonicalRejectsInvalidString(t *testing.T) {
	if _, err := Canonical(string([]byte{0xff})); !errors.Is(err, ErrInvalidString) {
		t.Fatalf("expected invalid string error, got %v", err)
	}
}

func TestCanonicalEscapesSpecialStrings(t *testing.T) {
	got, err := Canonical("\"\\\b\f\r\t")
	if err != nil {
		t.Fatal(err)
	}
	const want = `"\"\\\b\f\r\t"`
	if string(got) != want {
		t.Fatalf("canonical mismatch: got %s want %s", got, want)
	}
}

func TestCanonicalEscapesUnitSeparator(t *testing.T) {
	got, err := Canonical("\x1f")
	if err != nil {
		t.Fatal(err)
	}
	const want = `"\u001f"`
	if string(got) != want {
		t.Fatalf("canonical mismatch: got %s want %s", got, want)
	}
}

func TestCanonicalEncodesUntypedNilAsNull(t *testing.T) {
	got, err := Canonical(nil)
	if err != nil {
		t.Fatal(err)
	}
	if string(got) != "null" {
		t.Fatalf("canonical mismatch: got %s want null", got)
	}
}

func TestCanonicalEncodesFalseBool(t *testing.T) {
	got, err := Canonical(false)
	if err != nil {
		t.Fatal(err)
	}
	if string(got) != "false" {
		t.Fatalf("canonical mismatch: got %s want false", got)
	}
}

func TestCanonicalRejectsInvalidSliceElement(t *testing.T) {
	if _, err := Canonical([]any{1.5}); !errors.Is(err, ErrUnsupportedType) {
		t.Fatalf("expected unsupported type error, got %v", err)
	}
}

func TestCanonicalRejectsOverflowingJSONNumber(t *testing.T) {
	if _, err := Canonical(json.Number("999999999999999999999999999999")); err == nil {
		t.Fatalf("expected overflow error for oversized json.Number")
	}
}

func TestCanonicalRejectsInvalidMapKeyString(t *testing.T) {
	if _, err := Canonical(map[string]any{string([]byte{0xff}): "x"}); !errors.Is(err, ErrInvalidString) {
		t.Fatalf("expected invalid string error, got %v", err)
	}
}
