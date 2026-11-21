package inventory

import (
	"encoding/binary"
	"testing"
)

// ataField writes s into IDENTIFY data from byte off as ATA strings are
// laid out: two characters a word, the first in its high byte, padded with
// spaces to n bytes.
func ataField(id []byte, off, n int, s string) {
	b := []byte(s)
	for len(b) < n {
		b = append(b, ' ')
	}
	for i := 0; i < n; i += 2 {
		id[off+i], id[off+i+1] = b[i+1], b[i]
	}
}

// vpd89 is an ATA Information VPD page as libata builds it, constructed
// here: page code 89h, length 238h, IDENTIFY DEVICE's command code at byte
// 56 and its data from byte 60.
func vpd89(serial, firmware, model string) []byte {
	b := make([]byte, 572)
	b[1] = 0x89
	binary.BigEndian.PutUint16(b[2:], 572-4)
	b[56] = 0xEC
	id := b[60:]
	ataField(id, 20, 20, serial)
	ataField(id, 46, 8, firmware)
	ataField(id, 54, 40, model)
	return b
}

func TestParseVPD89(t *testing.T) {
	page := vpd89("TESTSERIAL0001", "82.00A82", "WDC WD10EFRX-68FYTN0")
	id, ok := parseVPD89(page)
	if !ok || len(id) != 512 {
		t.Fatalf("page refused: %d bytes, %v", len(id), ok)
	}
	if serial, firmware := ataIdentityStrings(id); serial != "TESTSERIAL0001" || firmware != "82.00A82" {
		t.Errorf("serial %q, firmware %q", serial, firmware)
	}
	// A longer page (the kernel's buffer) is read up to the IDENTIFY data.
	if _, ok := parseVPD89(append(page, make([]byte, 100)...)); !ok {
		t.Error("a longer page refused")
	}
	for name, mutate := range map[string]func(b []byte) []byte{
		"truncated":         func(b []byte) []byte { return b[:571] },
		"another page":      func(b []byte) []byte { b[1] = 0x80; return b },
		"short length":      func(b []byte) []byte { binary.BigEndian.PutUint16(b[2:], 100); return b },
		"not IDENTIFY data": func(b []byte) []byte { b[56] = 0xA1; return b },
		"empty":             func([]byte) []byte { return nil },
	} {
		b := vpd89("S", "F", "M")
		if _, ok := parseVPD89(mutate(b)); ok {
			t.Errorf("%s: accepted", name)
		}
	}
}

func TestParseVPD80(t *testing.T) {
	page := append([]byte{0, 0x80, 0, 12}, "  Z1Z2ABCD  "...)
	if got := parseVPD80(page); got != "Z1Z2ABCD" {
		t.Errorf("serial %q", got)
	}
	// A length past the end is cut to what is there; control characters
	// become spaces.
	if got := parseVPD80(append([]byte{0, 0x80, 0, 200}, "AB\x00CD"...)); got != "AB CD" {
		t.Errorf("long length: %q", got)
	}
	for _, b := range [][]byte{nil, {0, 0x80, 0}, append([]byte{0, 0x83, 0, 4}, "ABCD"...)} {
		if got := parseVPD80(b); got != "" {
			t.Errorf("%x = %q", b, got)
		}
	}
}

func FuzzParseVPD89(f *testing.F) {
	f.Add(vpd89("TESTSERIAL0001", "82.00A82", "WDC WD10EFRX-68FYTN0"))
	f.Add([]byte{0, 0x89, 2, 0x38})
	f.Fuzz(func(t *testing.T, b []byte) {
		if id, ok := parseVPD89(b); ok {
			_, _ = ataIdentityStrings(id)
		}
		_ = parseVPD80(b)
	})
}
