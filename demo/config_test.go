package main

import (
	"bytes"
	"testing"
)

func TestTrustAnchorID(t *testing.T) {
	invalidTests := []string{"nope", "-1.-1", "1..2", "1.", ".1", "4294967296"}
	for _, test := range invalidTests {
		_, ok := TrustAnchorIDFromString(test)
		if ok {
			t.Errorf("TrustAnchorIDFromString(%q) unexpected succeeded", test)
		}
	}

	var validTests = []struct {
		str string
		id  []byte
	}{
		{"32473.1", []byte{0x81, 0xfd, 0x59, 0x01}},
		{"4294967295", []byte{0x8f, 0xff, 0xff, 0xff, 0x7f}},
	}
	for _, tt := range validTests {
		id, ok := TrustAnchorIDFromString(tt.str)
		if !ok {
			t.Errorf("TrustAnchorIDFromString(%q) unexpected failed", tt.str)
			continue
		}
		if !bytes.Equal(id, tt.id) {
			t.Errorf("TrustAnchorIDFromString(%q) was %x, wanted %x", tt.str, []byte(id), tt.id)
			continue
		}
		if id.String() != tt.str {
			t.Errorf("id.String() was %s, wanted %s", id, tt.str)
			continue
		}
	}
}
