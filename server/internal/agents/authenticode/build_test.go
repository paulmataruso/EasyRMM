package authenticode

import (
	"crypto"
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/asn1"
	"encoding/binary"
	"errors"
	"math/big"
	"testing"
	"time"

	"golang.org/x/crypto/cryptobyte"
	cbasn1 "golang.org/x/crypto/cryptobyte/asn1"
)

// The tests below sign tiny.exe themselves, with keys made for each run,
// so that every part of the signature can be changed on its own and each
// refusal is reached through an otherwise valid signature.

var (
	oidSHA1   = asn1.ObjectIdentifier{1, 3, 14, 3, 2, 26}
	oidSHA256 = asn1.ObjectIdentifier{2, 16, 840, 1, 101, 3, 4, 2, 1}
	oidSHA384 = asn1.ObjectIdentifier{2, 16, 840, 1, 101, 3, 4, 2, 2}
	oidData   = asn1.ObjectIdentifier{1, 2, 840, 113549, 1, 7, 1}
	oidRSA    = asn1.ObjectIdentifier{1, 2, 840, 113549, 1, 1, 1}
)

// signing says how build signs tiny.exe; its zero value makes a valid
// signature with SHA-256 and an ECDSA P-256 key for code signing.
type signing struct {
	key  crypto.Signer // default: a new ECDSA P-256 key
	eku  []x509.ExtKeyUsage
	hash crypto.Hash // of the program's digest and the signer's; default SHA-256

	outerType   asn1.ObjectIdentifier // ContentInfo's type
	contentType asn1.ObjectIdentifier // the signed content's type
	dataKind    asn1.ObjectIdentifier // SpcAttributeTypeAndOptionalValue's type
	digestAlg   asn1.ObjectIdentifier // the program digest's algorithm
	signerAlg   asn1.ObjectIdentifier // the signer's digest algorithm
	digest      []byte                // the program's digest as signed
	noCerts     bool
	crls        bool
	signers     int // SignerInfos; default 1
	siVersion   int // default 1
	noAttrs     bool
	attrs       func(contentType asn1.ObjectIdentifier, msgDigest []byte) [][]byte // the signed attributes, each encoded
	msgDigest   []byte                                                             // the messageDigest attribute
	unsigned    []byte                                                             // the unsigned attributes' contents
	sig         func([]byte) []byte                                                // changes the signature value

	revision uint16 // WIN_CERTIFICATE; default 0x0200
}

func addOID(b *cryptobyte.Builder, o asn1.ObjectIdentifier) { b.AddASN1ObjectIdentifier(o) }

func algorithm(b *cryptobyte.Builder, o asn1.ObjectIdentifier) {
	b.AddASN1(cbasn1.SEQUENCE, func(b *cryptobyte.Builder) {
		addOID(b, o)
		b.AddASN1NULL()
	})
}

func attribute(o asn1.ObjectIdentifier, value func(*cryptobyte.Builder)) []byte {
	var b cryptobyte.Builder
	b.AddASN1(cbasn1.SEQUENCE, func(b *cryptobyte.Builder) {
		addOID(b, o)
		b.AddASN1(cbasn1.SET, value)
	})
	return b.BytesOrPanic()
}

func hashOID(h crypto.Hash) asn1.ObjectIdentifier {
	if h == crypto.SHA384 {
		return oidSHA384
	}
	return oidSHA256
}

// build signs tiny.exe as s says and returns the signed program.
func build(t *testing.T, s signing) []byte {
	t.Helper()
	program := read(t, "tiny.exe")
	if s.hash == 0 {
		s.hash = crypto.SHA256
	}
	if s.key == nil {
		k, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
		if err != nil {
			t.Fatal(err)
		}
		s.key = k
	}
	if s.eku == nil {
		s.eku = []x509.ExtKeyUsage{x509.ExtKeyUsageCodeSigning}
	}
	tmpl := &x509.Certificate{
		SerialNumber: big.NewInt(4242),
		Subject:      pkix.Name{CommonName: "EasyRMM built test signer"},
		NotBefore:    time.Now().Add(-time.Hour),
		NotAfter:     time.Now().Add(time.Hour),
		ExtKeyUsage:  s.eku,
	}
	certDER, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, s.key.Public(), s.key)
	if err != nil {
		t.Fatal(err)
	}
	cert, err := x509.ParseCertificate(certDER)
	if err != nil {
		t.Fatal(err)
	}

	if s.digest == nil {
		if s.digest, err = Digest(program, s.hash); err != nil {
			t.Fatal(err)
		}
	}
	orOID := func(o, def asn1.ObjectIdentifier) asn1.ObjectIdentifier {
		if o != nil {
			return o
		}
		return def
	}
	// SpcIndirectDataContent; the messageDigest attribute covers its contents.
	var spcB cryptobyte.Builder
	spcB.AddASN1(cbasn1.SEQUENCE, func(b *cryptobyte.Builder) {
		addOID(b, orOID(s.dataKind, oidSpcPEImageData))
		b.AddASN1(cbasn1.SEQUENCE, func(*cryptobyte.Builder) {}) // SpcPeImageData, empty
	})
	spcB.AddASN1(cbasn1.SEQUENCE, func(b *cryptobyte.Builder) {
		algorithm(b, orOID(s.digestAlg, hashOID(s.hash)))
		b.AddASN1OctetString(s.digest)
	})
	spc := spcB.BytesOrPanic()

	if s.msgDigest == nil {
		h := s.hash.New()
		h.Write(spc)
		s.msgDigest = h.Sum(nil)
	}
	if s.attrs == nil {
		s.attrs = func(ct asn1.ObjectIdentifier, md []byte) [][]byte {
			return [][]byte{
				attribute(oidContentType, func(b *cryptobyte.Builder) { addOID(b, ct) }),
				attribute(oidMessageDigest, func(b *cryptobyte.Builder) { b.AddASN1OctetString(md) }),
			}
		}
	}
	var attrs []byte
	for _, a := range s.attrs(oidSpcIndirectData, s.msgDigest) {
		attrs = append(attrs, a...)
	}
	var setB cryptobyte.Builder
	setB.AddASN1(cbasn1.SET, func(b *cryptobyte.Builder) { b.AddBytes(attrs) })
	h := s.hash.New()
	h.Write(setB.BytesOrPanic())
	var sig []byte
	switch k := s.key.(type) {
	case ed25519.PrivateKey:
		sig = ed25519.Sign(k, h.Sum(nil))
	default:
		if sig, err = s.key.Sign(rand.Reader, h.Sum(nil), s.hash); err != nil {
			t.Fatal(err)
		}
	}
	if s.sig != nil {
		sig = s.sig(sig)
	}

	signerInfo := func(b *cryptobyte.Builder) {
		b.AddASN1(cbasn1.SEQUENCE, func(b *cryptobyte.Builder) {
			v := s.siVersion
			if v == 0 {
				v = 1
			}
			b.AddASN1Int64(int64(v))
			b.AddASN1(cbasn1.SEQUENCE, func(b *cryptobyte.Builder) {
				b.AddBytes(cert.RawIssuer)
				b.AddASN1BigInt(cert.SerialNumber)
			})
			algorithm(b, orOID(s.signerAlg, hashOID(s.hash)))
			if !s.noAttrs {
				b.AddASN1(tagContext0, func(b *cryptobyte.Builder) { b.AddBytes(attrs) })
			}
			algorithm(b, oidRSA) // read past, not checked
			b.AddASN1OctetString(sig)
			if s.unsigned != nil {
				b.AddASN1(tagContext1, func(b *cryptobyte.Builder) { b.AddBytes(s.unsigned) })
			}
		})
	}

	var p7 cryptobyte.Builder
	p7.AddASN1(cbasn1.SEQUENCE, func(b *cryptobyte.Builder) {
		addOID(b, orOID(s.outerType, oidSignedData))
		b.AddASN1(tagContext0, func(b *cryptobyte.Builder) {
			b.AddASN1(cbasn1.SEQUENCE, func(b *cryptobyte.Builder) {
				b.AddASN1Int64(1)
				b.AddASN1(cbasn1.SET, func(b *cryptobyte.Builder) { algorithm(b, hashOID(s.hash)) })
				b.AddASN1(cbasn1.SEQUENCE, func(b *cryptobyte.Builder) {
					addOID(b, orOID(s.contentType, oidSpcIndirectData))
					b.AddASN1(tagContext0, func(b *cryptobyte.Builder) {
						b.AddASN1(cbasn1.SEQUENCE, func(b *cryptobyte.Builder) { b.AddBytes(spc) })
					})
				})
				if !s.noCerts {
					b.AddASN1(tagContext0, func(b *cryptobyte.Builder) { b.AddBytes(certDER) })
				}
				if s.crls {
					b.AddASN1(tagContext1, func(*cryptobyte.Builder) {})
				}
				b.AddASN1(cbasn1.SET, func(b *cryptobyte.Builder) {
					n := s.signers
					if n == 0 {
						n = 1
					}
					for range n {
						signerInfo(b)
					}
				})
			})
		})
	})
	return embed(t, program, p7.BytesOrPanic(), s.revision)
}

// embed appends a certificate table holding pkcs7 to an unsigned program,
// as signing tools do.
func embed(t *testing.T, program, pkcs7 []byte, revision uint16) []byte {
	t.Helper()
	if revision == 0 {
		revision = 0x0200
	}
	l, err := readLayout(program)
	if err != nil || l.certAddr != 0 {
		t.Fatalf("not an unsigned program: %v", err)
	}
	out := append([]byte(nil), program...)
	for len(out)%8 != 0 {
		out = append(out, 0)
	}
	at := len(out)
	entry := make([]byte, 8, 8+len(pkcs7)+7)
	binary.LittleEndian.PutUint32(entry, uint32(8+len(pkcs7)))
	binary.LittleEndian.PutUint16(entry[4:], revision)
	binary.LittleEndian.PutUint16(entry[6:], 2) // WIN_CERT_TYPE_PKCS_SIGNED_DATA
	entry = append(entry, pkcs7...)
	for len(entry)%8 != 0 {
		entry = append(entry, 0)
	}
	out = append(out, entry...)
	binary.LittleEndian.PutUint32(out[l.certEntry:], uint32(at))
	binary.LittleEndian.PutUint32(out[l.certEntry+4:], uint32(len(entry)))
	return out
}

func TestBuiltSignatures(t *testing.T) {
	rsaKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}
	_, edKey, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	for _, c := range []struct {
		name string
		s    signing
	}{
		{"ECDSA, SHA-256", signing{}},
		{"RSA, SHA-384", signing{key: rsaKey, hash: crypto.SHA384}},
		{"a certificate for any use", signing{eku: []x509.ExtKeyUsage{x509.ExtKeyUsageAny}}},
		{"a certificate with no extended key usage", signing{eku: []x509.ExtKeyUsage{}}},
		{"an empty list of revoked certificates", signing{crls: true}},
		{"other unsigned attributes", signing{unsigned: attribute(oidData, func(b *cryptobyte.Builder) { b.AddASN1Int64(1) })}},
		{"other signed attributes", signing{attrs: func(ct asn1.ObjectIdentifier, md []byte) [][]byte {
			return [][]byte{
				attribute(oidData, func(b *cryptobyte.Builder) { b.AddASN1Int64(7) }),
				attribute(oidContentType, func(b *cryptobyte.Builder) { addOID(b, ct) }),
				attribute(oidMessageDigest, func(b *cryptobyte.Builder) { b.AddASN1OctetString(md) }),
			}
		}}},
	} {
		sig, err := Verify(build(t, c.s))
		if err != nil {
			t.Errorf("%s: %v", c.name, err)
			continue
		}
		if sig.Signer.Subject.CommonName != "EasyRMM built test signer" || sig.Timestamped || sig.Nested != 0 {
			t.Errorf("%s: %+v", c.name, sig)
		}
		if want := c.s.hash; want != 0 && sig.Hash != want {
			t.Errorf("%s: hash %v", c.name, sig.Hash)
		}
	}

	only := func(contentType asn1.ObjectIdentifier, md []byte, which ...asn1.ObjectIdentifier) func(asn1.ObjectIdentifier, []byte) [][]byte {
		return func(asn1.ObjectIdentifier, []byte) [][]byte {
			var out [][]byte
			for _, w := range which {
				switch {
				case w.Equal(oidContentType):
					out = append(out, attribute(oidContentType, func(b *cryptobyte.Builder) { addOID(b, contentType) }))
				case w.Equal(oidMessageDigest):
					out = append(out, attribute(oidMessageDigest, func(b *cryptobyte.Builder) { b.AddASN1OctetString(md) }))
				}
			}
			return out
		}
	}
	md := make([]byte, 32)
	for _, c := range []struct {
		name string
		s    signing
		want error
	}{
		{"not SignedData", signing{outerType: oidData}, ErrUnsupported},
		{"not SpcIndirectDataContent", signing{contentType: oidData}, ErrUnsupported},
		{"not a program's signature", signing{dataKind: oidData}, ErrUnsupported},
		{"a SHA-1 digest", signing{digestAlg: oidSHA1}, ErrUnsupported},
		{"a SHA-1 signer", signing{signerAlg: oidSHA1}, ErrUnsupported},
		{"another program's digest", signing{digest: make([]byte, 32)}, ErrChanged},
		{"no certificates", signing{noCerts: true}, ErrMalformed},
		{"two signers", signing{signers: 2}, ErrSignatures},
		{"a signer identified by key", signing{siVersion: 3}, ErrUnsupported},
		{"no signed attributes", signing{noAttrs: true}, ErrMalformed},
		{"no content type", signing{attrs: only(oidSpcIndirectData, md, oidMessageDigest)}, ErrMalformed},
		{"no message digest", signing{attrs: only(oidSpcIndirectData, md, oidContentType)}, ErrMalformed},
		{"two content types", signing{attrs: only(oidSpcIndirectData, md, oidContentType, oidContentType, oidMessageDigest)}, ErrMalformed},
		{"two message digests", signing{attrs: only(oidSpcIndirectData, md, oidContentType, oidMessageDigest, oidMessageDigest)}, ErrMalformed},
		{"a signed content type that is not the content's", signing{attrs: func(_ asn1.ObjectIdentifier, md []byte) [][]byte {
			return only(oidData, md, oidContentType, oidMessageDigest)(nil, nil)
		}}, ErrMalformed},
		{"a message digest of something else", signing{msgDigest: md}, ErrBadSignature},
		{"a damaged ECDSA signature", signing{sig: func(b []byte) []byte { return append([]byte{}, b[:len(b)-1]...) }}, ErrBadSignature},
		{"an Ed25519 key", signing{key: edKey}, ErrUnsupported},
		{"a damaged nested signature", signing{unsigned: attribute(oidNestedSignature, func(b *cryptobyte.Builder) { b.AddASN1Int64(1) })}, ErrMalformed},
		{"a damaged unsigned attribute", signing{unsigned: []byte{0x30, 0x03, 0x02, 0x01, 0x01}}, ErrMalformed},
		{"a WIN_CERTIFICATE of another revision", signing{revision: 0x0100}, ErrUnsupported},
	} {
		if _, err := Verify(build(t, c.s)); !errors.Is(err, c.want) {
			t.Errorf("%s: %v, want %v", c.name, err, c.want)
		}
	}
}

func TestVerifyRefusesDamagedTables(t *testing.T) {
	signed := build(t, signing{})
	l, err := readLayout(signed)
	if err != nil {
		t.Fatal(err)
	}
	// A WIN_CERTIFICATE whose length is shorter than its header, or longer
	// than the table.
	for _, length := range []uint32{4, uint32(l.certSize) + 8} {
		b := append([]byte(nil), signed...)
		binary.LittleEndian.PutUint32(b[l.certAddr:], length)
		if _, err := Verify(b); !errors.Is(err, ErrMalformed) {
			t.Errorf("length %d: %v", length, err)
		}
	}
	// A table too short for a WIN_CERTIFICATE.
	b := append([]byte(nil), signed[:l.certAddr+8]...)
	binary.LittleEndian.PutUint32(b[l.certEntry+4:], 4)
	b = b[:l.certAddr+4]
	if _, err := Verify(b); !errors.Is(err, ErrMalformed) {
		t.Errorf("short table: %v", err)
	}
	// A table that does not start on 8 bytes.
	b = append([]byte(nil), signed...)
	binary.LittleEndian.PutUint32(b[l.certEntry:], uint32(l.certAddr+4))
	binary.LittleEndian.PutUint32(b[l.certEntry+4:], uint32(l.certSize-4))
	if _, err := Verify(b); !errors.Is(err, ErrMalformed) {
		t.Errorf("misaligned table: %v", err)
	}
	// PKCS #7 data that is not DER.
	b = append([]byte(nil), signed...)
	b[l.certAddr+8] = 0x04
	if _, err := Verify(b); !errors.Is(err, ErrMalformed) {
		t.Errorf("not a SEQUENCE: %v", err)
	}
}

func TestReadLayoutRefuses(t *testing.T) {
	tiny := read(t, "tiny.exe")
	pe := int(binary.LittleEndian.Uint32(tiny[0x3c:]))
	opt := pe + 24
	change := func(f func(b []byte)) []byte {
		b := append([]byte(nil), tiny...)
		f(b)
		return b
	}
	for _, c := range []struct {
		name string
		data []byte
	}{
		{"no PE signature", change(func(b []byte) { b[pe] = 'X' })},
		{"a PE header past the end", change(func(b []byte) { binary.LittleEndian.PutUint32(b[0x3c:], uint32(len(b))) })},
		{"an optional header past the end", change(func(b []byte) { binary.LittleEndian.PutUint16(b[pe+20:], 0xffff) })},
		{"an optional header of another kind", change(func(b []byte) { binary.LittleEndian.PutUint16(b[opt:], 0x107) })},
		{"too few data directories", change(func(b []byte) { binary.LittleEndian.PutUint32(b[opt+108:], 4) })},
	} {
		if _, err := Digest(c.data, crypto.SHA256); !errors.Is(err, ErrNotProgram) {
			t.Errorf("%s: %v", c.name, err)
		}
	}
	// A 32-bit program's optional header puts its count of data directories
	// and the directories 16 bytes earlier.
	pe32 := change(func(b []byte) {
		binary.LittleEndian.PutUint16(b[opt:], 0x10b)
		binary.LittleEndian.PutUint32(b[opt+92:], 16)
	})
	if l, err := readLayout(pe32); err != nil || l.certEntry != opt+96+4*8 {
		t.Errorf("PE32: %+v %v", l, err)
	}
	if _, err := Digest(tiny, crypto.MD4); !errors.Is(err, ErrUnsupported) {
		t.Errorf("MD4: %v", err)
	}
}
