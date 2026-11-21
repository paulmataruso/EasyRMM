package authenticode

import (
	"bytes"
	"crypto"
	"encoding/binary"
	"encoding/hex"
	"errors"
	"os"
	"path/filepath"
	"testing"
)

// The test programs are described in testdata/README.md: tiny.exe and copies
// of it signed by osslsigncode 2.9 with throwaway certificates.

func read(t *testing.T, name string) []byte {
	t.Helper()
	b, err := os.ReadFile(filepath.Join("testdata", name))
	if err != nil {
		t.Fatal(err)
	}
	return b
}

// tinyDigest is tiny.exe's Authenticode digest as osslsigncode computes it
// ("Calculated message digest" in osslsigncode verify).
const tinyDigest = "84b2a4ab3e968aa5629971c20af3e4295a7654ffa5d09a0204e8471489682864"

func TestDigestMatchesOsslsigncode(t *testing.T) {
	for _, name := range []string{"tiny.exe", "tiny-rsa.exe", "tiny-ecdsa.exe", "tiny-nested.exe", "tiny-rfc3161.exe", "tiny-legacy-ts.exe"} {
		d, err := Digest(read(t, name), crypto.SHA256)
		if err != nil {
			t.Fatalf("%s: %v", name, err)
		}
		if got := hex.EncodeToString(d); got != tinyDigest {
			t.Errorf("%s: digest %s, want %s", name, got, tinyDigest)
		}
	}
}

func TestDigestPadsAnUnsignedProgram(t *testing.T) {
	// Signing tools add zeros up to a multiple of 8 bytes before the
	// signature table, and the digest then covers them.
	tiny := read(t, "tiny.exe")
	odd := append(append([]byte{}, tiny...), 0x41, 0x42, 0x43)
	padded := append(append([]byte{}, odd...), 0, 0, 0, 0, 0)
	a, err := Digest(odd, crypto.SHA256)
	if err != nil {
		t.Fatal(err)
	}
	b, err := Digest(padded, crypto.SHA256)
	if err != nil {
		t.Fatal(err)
	}
	if hex.EncodeToString(a) != hex.EncodeToString(b) {
		t.Error("an unsigned program's digest does not count the padding a signature adds")
	}
}

func TestVerify(t *testing.T) {
	for _, c := range []struct {
		name, signer string
		nested       int
		timestamped  bool
	}{
		{"tiny-rsa.exe", "EasyRMM test signer (rsa)", 0, false},
		{"tiny-ecdsa.exe", "EasyRMM test signer (ecdsa)", 0, false},
		{"tiny-nested.exe", "EasyRMM test signer (rsa)", 1, false},
		// signtool /tr: an RFC 3161 timestamp in an unsigned attribute.
		{"tiny-rfc3161.exe", "EasyRMM test signer (timestamped)", 0, true},
		// signtool /t: an Authenticode countersignature.
		{"tiny-legacy-ts.exe", "EasyRMM test signer (timestamped)", 0, true},
	} {
		sig, err := Verify(read(t, c.name))
		if err != nil {
			t.Fatalf("%s: %v", c.name, err)
		}
		if sig.Signer.Subject.CommonName != c.signer || sig.Certificates[0] != sig.Signer {
			t.Errorf("%s: signer %q", c.name, sig.Signer.Subject.CommonName)
		}
		if sig.Hash != crypto.SHA256 || hex.EncodeToString(sig.Digest) != tinyDigest {
			t.Errorf("%s: %v %x", c.name, sig.Hash, sig.Digest)
		}
		if sig.Timestamped != c.timestamped {
			t.Errorf("%s: timestamped %v, want %v", c.name, sig.Timestamped, c.timestamped)
		}
		if sig.Nested != c.nested {
			t.Errorf("%s: %d nested signatures, want %d", c.name, sig.Nested, c.nested)
		}
	}
}

// certTable returns the offset and length of a signed program's one
// WIN_CERTIFICATE's PKCS #7 data.
func certTable(t *testing.T, b []byte) (int, int) {
	t.Helper()
	l, err := readLayout(b)
	if err != nil || l.certAddr == 0 {
		t.Fatalf("not signed: %v", err)
	}
	return l.certAddr + 8, int(binary.LittleEndian.Uint32(b[l.certAddr:])) - 8
}

func TestVerifyRefuses(t *testing.T) {
	changedCode := read(t, "tiny-rsa.exe")
	changedCode[0x400] ^= 0xff // in the first section

	badSignature := read(t, "tiny-rsa.exe")
	at, n := certTable(t, badSignature)
	sd, err := parseSignedData(badSignature[at : at+n])
	if err != nil {
		t.Fatal(err)
	}
	badSignature[at+bytes.Index(badSignature[at:at+n], sd.sig)+10] ^= 0x01

	afterSignature := read(t, "tiny-rsa.exe")
	afterSignature[at+n-1] ^= 0x01 // the padding after the signature

	trailing := append(read(t, "tiny-rsa.exe"), 0, 0, 0, 0, 0, 0, 0, 0)

	second := read(t, "tiny-rsa.exe")
	{
		l, _ := readLayout(second)
		entry := second[l.certAddr:]
		second = append(second, entry...) // the same signature again, as a second entry
		binary.LittleEndian.PutUint32(second[l.certEntry+4:], uint32(2*l.certSize))
	}

	for _, c := range []struct {
		name string
		data []byte
		want error
	}{
		{"unsigned", read(t, "tiny.exe"), ErrUnsigned},
		{"not a program", []byte("MZ but nothing else at all, not even a PE header....................."), ErrNotProgram},
		{"empty", nil, ErrNotProgram},
		{"changed after signing", changedCode, ErrChanged},
		{"a damaged signature", badSignature, ErrBadSignature},
		{"a server certificate", read(t, "tiny-noeku.exe"), ErrNotForCode},
		{"data after the signature table", trailing, ErrMalformed},
		{"data after the signature", afterSignature, ErrMalformed},
		{"two signatures", second, ErrSignatures},
	} {
		if _, err := Verify(c.data); !errors.Is(err, c.want) {
			t.Errorf("%s: %v, want %v", c.name, err, c.want)
		}
	}
}

// FuzzVerify checks that no file makes Verify or Digest panic: they read
// what operators upload.
func FuzzVerify(f *testing.F) {
	for _, name := range []string{"tiny.exe", "tiny-rsa.exe", "tiny-ecdsa.exe", "tiny-nested.exe"} {
		b, err := os.ReadFile(filepath.Join("testdata", name))
		if err != nil {
			f.Fatal(err)
		}
		f.Add(b)
	}
	f.Fuzz(func(t *testing.T, b []byte) {
		_, _ = Verify(b)
		_, _ = Digest(b, crypto.SHA256)
	})
}
