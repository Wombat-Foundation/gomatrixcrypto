package matrixjson

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"reflect"
	"sort"
	"strconv"
	"strings"
	"unicode/utf8"
)

const (
	maxCanonicalInt = int64(1<<53 - 1)
	minCanonicalInt = -maxCanonicalInt
)

var (
	ErrUnsupportedType = errors.New("unsupported canonical json type")
	ErrIntegerRange    = errors.New("canonical json integer out of range")
	ErrInvalidString   = errors.New("canonical json string is not valid utf-8")
)

// Canonical encodes v using the Matrix Canonical JSON rules used for signing:
// sorted object keys, no insignificant whitespace, UTF-8 strings, and integers
// limited to JavaScript's exactly representable integer range.
func Canonical(v any) ([]byte, error) {
	var buf bytes.Buffer
	if err := appendValue(&buf, reflect.ValueOf(v)); err != nil {
		return nil, err
	}
	return buf.Bytes(), nil
}

func appendValue(buf *bytes.Buffer, v reflect.Value) error {
	if !v.IsValid() {
		buf.WriteString("null")
		return nil
	}
	for v.Kind() == reflect.Interface || v.Kind() == reflect.Pointer {
		if v.IsNil() {
			buf.WriteString("null")
			return nil
		}
		v = v.Elem()
	}
	if number, ok := v.Interface().(json.Number); ok {
		return appendJSONNumber(buf, number)
	}

	switch v.Kind() {
	case reflect.Bool:
		if v.Bool() {
			buf.WriteString("true")
		} else {
			buf.WriteString("false")
		}
		return nil
	case reflect.String:
		return appendString(buf, v.String())
	case reflect.Int, reflect.Int8, reflect.Int16, reflect.Int32, reflect.Int64:
		return appendInt(buf, v.Int())
	case reflect.Uint, reflect.Uint8, reflect.Uint16, reflect.Uint32, reflect.Uint64, reflect.Uintptr:
		u := v.Uint()
		if u > uint64(maxCanonicalInt) {
			return ErrIntegerRange
		}
		buf.WriteString(strconv.FormatUint(u, 10))
		return nil
	case reflect.Slice, reflect.Array:
		buf.WriteByte('[')
		for i := 0; i < v.Len(); i++ {
			if i > 0 {
				buf.WriteByte(',')
			}
			if err := appendValue(buf, v.Index(i)); err != nil {
				return err
			}
		}
		buf.WriteByte(']')
		return nil
	case reflect.Map:
		return appendMap(buf, v)
	default:
		return fmt.Errorf("%w: %s", ErrUnsupportedType, v.Type())
	}
}

func appendInt(buf *bytes.Buffer, n int64) error {
	if n < minCanonicalInt || n > maxCanonicalInt {
		return ErrIntegerRange
	}
	buf.WriteString(strconv.FormatInt(n, 10))
	return nil
}

func appendJSONNumber(buf *bytes.Buffer, n json.Number) error {
	s := n.String()
	if strings.ContainsAny(s, ".eE") {
		return fmt.Errorf("%w: %s", ErrUnsupportedType, "non-integer json.Number")
	}
	i, err := strconv.ParseInt(s, 10, 64)
	if err != nil {
		return err
	}
	return appendInt(buf, i)
}

func appendMap(buf *bytes.Buffer, v reflect.Value) error {
	if v.Type().Key().Kind() != reflect.String {
		return fmt.Errorf("%w: map key %s", ErrUnsupportedType, v.Type().Key())
	}

	keys := make([]string, 0, v.Len())
	for _, key := range v.MapKeys() {
		keys = append(keys, key.String())
	}
	sort.Strings(keys)

	buf.WriteByte('{')
	for i, key := range keys {
		if i > 0 {
			buf.WriteByte(',')
		}
		if err := appendString(buf, key); err != nil {
			return err
		}
		buf.WriteByte(':')
		if err := appendValue(buf, v.MapIndex(reflect.ValueOf(key))); err != nil {
			return err
		}
	}
	buf.WriteByte('}')
	return nil
}

func appendString(buf *bytes.Buffer, s string) error {
	if !utf8.ValidString(s) {
		return ErrInvalidString
	}

	buf.WriteByte('"')
	for _, r := range s {
		switch r {
		case '\\', '"':
			buf.WriteByte('\\')
			buf.WriteRune(r)
		case '\b':
			buf.WriteString(`\b`)
		case '\f':
			buf.WriteString(`\f`)
		case '\n':
			buf.WriteString(`\n`)
		case '\r':
			buf.WriteString(`\r`)
		case '\t':
			buf.WriteString(`\t`)
		default:
			if r < 0x20 {
				buf.WriteString(`\u00`)
				if r < 0x10 {
					buf.WriteByte('0')
				}
				buf.WriteString(strconv.FormatInt(int64(r), 16))
			} else {
				buf.WriteRune(r)
			}
		}
	}
	buf.WriteByte('"')
	return nil
}
