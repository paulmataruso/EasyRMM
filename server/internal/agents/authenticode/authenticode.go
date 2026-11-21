// Package authenticode reads the Authenticode signature of a Windows program
// and computes the digest that the signature covers, so that the server can
// tell that a file an operator signed is its own agent build with only a
// signature added (ADR-0049).
//
// It checks what the file itself proves: that the signature covers this
// file and that the signer's certificate made it. It does not check the
// certificate's chain, revocation or validity period; Windows decides those
// on each computer, against the certificates that computer trusts.
package authenticode

import (
	"bytes"
	"crypto"
	"crypto/ecdsa"
	"crypto/rsa"
	"crypto/x509"
	"encoding/asn1"
	"encoding/binary"
	"errors"
	"fmt"
	"hash"
	"math/big"

	"golang.org/x/crypto/cryptobyte"
	cbasn1 "golang.org/x/crypto/cryptobyte/asn1"

	// The digests Authenticode signatures use.
	_ "crypto/sha256"
	_ "crypto/sha512"
)

// Errors that say what is wrong with a file, for the person who uploaded it.
var (
	ErrNotProgram   = errors.New("this is not a Windows program")
	ErrUnsigned     = errors.New("this program has no Authenticode signature")
	ErrSignatures   = errors.New("this program's signature table holds more than one signature; sign it once (a nested signature is fine)")
	ErrChanged      = errors.New("the signature does not cover this file: it was changed after it was signed")
	ErrBadSignature = errors.New("the signature does not verify with the signer's certificate")
	ErrNotForCode   = errors.New("the signer's certificate is not for code signing")
	ErrUnsupported  = errors.New("the signature uses a format or algorithm EasyRMM does not read")
	ErrMalformed    = errors.New("the signature is damaged or not in Authenticode's format")
)

var (
	oidSignedData       = asn1.ObjectIdentifier{1, 2, 840, 113549, 1, 7, 2}
	oidSpcIndirectData  = asn1.ObjectIdentifier{1, 3, 6, 1, 4, 1, 311, 2, 1, 4}
	oidSpcPEImageData   = asn1.ObjectIdentifier{1, 3, 6, 1, 4, 1, 311, 2, 1, 15}
	oidContentType      = asn1.ObjectIdentifier{1, 2, 840, 113549, 1, 9, 3}
	oidMessageDigest    = asn1.ObjectIdentifier{1, 2, 840, 113549, 1, 9, 4}
	oidCounterSignature = asn1.ObjectIdentifier{1, 2, 840, 113549, 1, 9, 6}
	oidRFC3161Timestamp = asn1.ObjectIdentifier{1, 3, 6, 1, 4, 1, 311, 3, 3, 1}
	oidNestedSignature  = asn1.ObjectIdentifier{1, 3, 6, 1, 4, 1, 311, 2, 4, 1}

	hashes = map[string]crypto.Hash{
		"2.16.840.1.101.3.4.2.1": crypto.SHA256,
		"2.16.840.1.101.3.4.2.2": crypto.SHA384,
		"2.16.840.1.101.3.4.2.3": crypto.SHA512,
	}
)

// Signature is a program's Authenticode signature, checked.
type Signature struct {
	// Hash is the digest algorithm of the program's digest.
	Hash crypto.Hash
	// Digest is the program's Authenticode digest, which the signature covers.
	Digest []byte
	// Signer is the certificate that made the signature.
	Signer *x509.Certificate
	// Certificates are all those the signature carries, the signer's first.
	Certificates []*x509.Certificate
	// Timestamped says the signature carries a timestamp, so that it stays
	// valid after the signer's certificate expires. The timestamp itself is
	// not checked.
	Timestamped bool
	// Nested counts further signatures nested in this one (signtool /as).
	// They are not checked.
	Nested int
}

// peLayout is where a PE file keeps what the Authenticode digest leaves out.
type peLayout struct {
	checksum  int // offset of the optional header's CheckSum
	certEntry int // offset of the certificate table's data directory entry
	certAddr  int // file offset of the certificate table; 0 when unsigned
	certSize  int
}

func readLayout(data []byte) (peLayout, error) {
	if len(data) < 0x40 || data[0] != 'M' || data[1] != 'Z' {
		return peLayout{}, ErrNotProgram
	}
	pe := int(binary.LittleEndian.Uint32(data[0x3c:]))
	if pe < 0x40 || pe > len(data)-24 || !bytes.Equal(data[pe:pe+4], []byte("PE\x00\x00")) {
		return peLayout{}, ErrNotProgram
	}
	optSize := int(binary.LittleEndian.Uint16(data[pe+20:]))
	opt := pe + 24
	if optSize < 2 || opt+optSize > len(data) {
		return peLayout{}, ErrNotProgram
	}
	var countAt, dirs int
	switch binary.LittleEndian.Uint16(data[opt:]) {
	case 0x10b: // PE32
		countAt, dirs = opt+92, opt+96
	case 0x20b: // PE32+
		countAt, dirs = opt+108, opt+112
	default:
		return peLayout{}, ErrNotProgram
	}
	const certDir = 4 // IMAGE_DIRECTORY_ENTRY_SECURITY
	certEntry := dirs + certDir*8
	if countAt+4 > opt+optSize || binary.LittleEndian.Uint32(data[countAt:]) <= certDir || certEntry+8 > opt+optSize {
		return peLayout{}, ErrNotProgram
	}
	l := peLayout{
		checksum:  opt + 64,
		certEntry: certEntry,
		certAddr:  int(binary.LittleEndian.Uint32(data[certEntry:])),
		certSize:  int(binary.LittleEndian.Uint32(data[certEntry+4:])),
	}
	if l.certSize == 0 {
		l.certAddr = 0
		return l, nil
	}
	// The table is the last thing in the file, after the headers, aligned to
	// 8 bytes, as signing tools place it; anything after it would be outside
	// what the signature covers.
	if l.certAddr < certEntry+8 || l.certAddr%8 != 0 || l.certAddr+l.certSize != len(data) {
		return peLayout{}, fmt.Errorf("%w: the signature table is not at the end of the file", ErrMalformed)
	}
	return l, nil
}

// Digest computes a program's Authenticode digest with h: the hash of the
// file without its CheckSum field, its certificate table's directory entry
// and the table itself. For an unsigned program it adds zeros up to a
// multiple of 8 bytes, as signing tools do before appending the table, so
// that a program and its signed copy have the same digest.
func Digest(data []byte, h crypto.Hash) ([]byte, error) {
	l, err := readLayout(data)
	if err != nil {
		return nil, err
	}
	if !h.Available() {
		return nil, ErrUnsupported
	}
	return digest(data, l, h.New()), nil
}

func digest(data []byte, l peLayout, w hash.Hash) []byte {
	end := len(data)
	if l.certAddr != 0 {
		end = l.certAddr
	}
	w.Write(data[:l.checksum])
	w.Write(data[l.checksum+4 : l.certEntry])
	w.Write(data[l.certEntry+8 : end])
	if l.certAddr == 0 && end%8 != 0 {
		w.Write(make([]byte, 8-end%8))
	}
	return w.Sum(nil)
}

// Verify reads a program's Authenticode signature and checks that it covers
// the program and that the signer's certificate made it.
func Verify(data []byte) (*Signature, error) {
	l, err := readLayout(data)
	if err != nil {
		return nil, err
	}
	if l.certAddr == 0 {
		return nil, ErrUnsigned
	}
	der, err := oneCertificate(data[l.certAddr : l.certAddr+l.certSize])
	if err != nil {
		return nil, err
	}
	sd, err := parseSignedData(der)
	if err != nil {
		return nil, err
	}
	// readHash knows only digests this package links, so the hash is available.
	got := digest(data, l, sd.hash.New())
	if !bytes.Equal(got, sd.digest) {
		return nil, ErrChanged
	}
	if err := sd.verify(); err != nil {
		return nil, err
	}
	certs := []*x509.Certificate{sd.signer}
	for _, c := range sd.certs {
		if c != sd.signer {
			certs = append(certs, c)
		}
	}
	return &Signature{
		Hash:         sd.hash,
		Digest:       got,
		Signer:       sd.signer,
		Certificates: certs,
		Timestamped:  sd.timestamped,
		Nested:       sd.nested,
	}, nil
}

// oneCertificate returns the PKCS #7 data of the one WIN_CERTIFICATE in a
// certificate table.
func oneCertificate(table []byte) ([]byte, error) {
	if len(table) < 8 {
		return nil, ErrMalformed
	}
	length := int(binary.LittleEndian.Uint32(table))
	revision := binary.LittleEndian.Uint16(table[4:])
	kind := binary.LittleEndian.Uint16(table[6:])
	if length < 8 || length > len(table) {
		return nil, ErrMalformed
	}
	if revision != 0x0200 || kind != 0x0002 { // WIN_CERT_REVISION_2_0, WIN_CERT_TYPE_PKCS_SIGNED_DATA
		return nil, ErrUnsupported
	}
	// Entries are padded to 8 bytes; another entry after this one is a
	// second signature.
	next := (length + 7) &^ 7
	if next < len(table) && !allZero(table[next:]) {
		return nil, ErrSignatures
	}
	return table[8:length], nil
}

func allZero(b []byte) bool {
	for _, c := range b {
		if c != 0 {
			return false
		}
	}
	return true
}

// signedData is what Verify needs from the PKCS #7 SignedData.
type signedData struct {
	hash   crypto.Hash // of the program's digest
	digest []byte
	// spc is the SpcIndirectDataContent's value, which the messageDigest
	// attribute covers.
	spc         []byte
	certs       []*x509.Certificate
	signer      *x509.Certificate
	signerHash  crypto.Hash
	attrs       []byte // the authenticated attributes, encoded as a SET
	contentType asn1.ObjectIdentifier
	msgDigest   []byte
	sig         []byte
	timestamped bool
	nested      int
}

var (
	tagContext0 = cbasn1.Tag(0).ContextSpecific().Constructed()
	tagContext1 = cbasn1.Tag(1).ContextSpecific().Constructed()
)

func parseSignedData(der []byte) (*signedData, error) {
	in := cryptobyte.String(der)
	var ci, explicit, sd cryptobyte.String
	var ct asn1.ObjectIdentifier
	if !in.ReadASN1(&ci, cbasn1.SEQUENCE) || !ci.ReadASN1ObjectIdentifier(&ct) {
		return nil, ErrMalformed
	}
	// Only padding may follow the signature: nothing covers it.
	if !allZero(in) {
		return nil, fmt.Errorf("%w: data follows the signature", ErrMalformed)
	}
	if !ct.Equal(oidSignedData) {
		return nil, ErrUnsupported
	}
	var version int
	var algs cryptobyte.String
	if !ci.ReadASN1(&explicit, tagContext0) || !explicit.ReadASN1(&sd, cbasn1.SEQUENCE) ||
		!sd.ReadASN1Integer(&version) || !sd.ReadASN1(&algs, cbasn1.SET) {
		return nil, ErrMalformed
	}

	out := &signedData{}
	if err := out.readContent(&sd); err != nil {
		return nil, err
	}
	if sd.PeekASN1Tag(tagContext0) {
		var certs cryptobyte.String
		if !sd.ReadASN1(&certs, tagContext0) {
			return nil, ErrMalformed
		}
		for !certs.Empty() {
			var c cryptobyte.String
			if !certs.ReadASN1Element(&c, cbasn1.SEQUENCE) {
				return nil, ErrMalformed
			}
			cert, err := x509.ParseCertificate(c)
			if err != nil {
				return nil, fmt.Errorf("%w: a certificate: %w", ErrMalformed, err)
			}
			out.certs = append(out.certs, cert)
		}
	}
	if sd.PeekASN1Tag(tagContext1) && !sd.SkipASN1(tagContext1) { // CRLs
		return nil, ErrMalformed
	}
	var signers, si cryptobyte.String
	if !sd.ReadASN1(&signers, cbasn1.SET) || !signers.ReadASN1(&si, cbasn1.SEQUENCE) {
		return nil, ErrMalformed
	}
	if !signers.Empty() {
		return nil, ErrSignatures
	}
	if err := out.readSigner(si); err != nil {
		return nil, err
	}
	return out, nil
}

// readContent reads the SpcIndirectDataContent: what is signed, and its digest.
func (s *signedData) readContent(sd *cryptobyte.String) error {
	var content, explicit, spc, data, digestInfo, digest cryptobyte.String
	var ct, kind asn1.ObjectIdentifier
	if !sd.ReadASN1(&content, cbasn1.SEQUENCE) || !content.ReadASN1ObjectIdentifier(&ct) {
		return ErrMalformed
	}
	if !ct.Equal(oidSpcIndirectData) {
		return ErrUnsupported
	}
	if !content.ReadASN1(&explicit, tagContext0) || !explicit.ReadASN1(&spc, cbasn1.SEQUENCE) {
		return ErrMalformed
	}
	s.spc = spc
	if !spc.ReadASN1(&data, cbasn1.SEQUENCE) || !data.ReadASN1ObjectIdentifier(&kind) ||
		!spc.ReadASN1(&digestInfo, cbasn1.SEQUENCE) {
		return ErrMalformed
	}
	if !kind.Equal(oidSpcPEImageData) {
		return fmt.Errorf("%w: it is not a signature of a program", ErrUnsupported)
	}
	h, err := readHash(&digestInfo)
	if err != nil {
		return err
	}
	if !digestInfo.ReadASN1(&digest, cbasn1.OCTET_STRING) {
		return ErrMalformed
	}
	s.hash, s.digest = h, digest
	return nil
}

// readHash reads an AlgorithmIdentifier naming a digest.
func readHash(in *cryptobyte.String) (crypto.Hash, error) {
	var alg cryptobyte.String
	var oid asn1.ObjectIdentifier
	if !in.ReadASN1(&alg, cbasn1.SEQUENCE) || !alg.ReadASN1ObjectIdentifier(&oid) {
		return 0, ErrMalformed
	}
	h, ok := hashes[oid.String()]
	if !ok {
		return 0, fmt.Errorf("%w: the digest algorithm %s (use SHA-256, SHA-384 or SHA-512)", ErrUnsupported, oid)
	}
	return h, nil
}

func (s *signedData) readSigner(si cryptobyte.String) error {
	var version int
	var sid, issuer cryptobyte.String
	serial := new(big.Int)
	if !si.ReadASN1Integer(&version) || !si.ReadASN1(&sid, cbasn1.SEQUENCE) ||
		!sid.ReadASN1Element(&issuer, cbasn1.SEQUENCE) || !sid.ReadASN1Integer(serial) {
		return ErrMalformed
	}
	if version != 1 {
		return ErrUnsupported
	}
	for _, c := range s.certs {
		if bytes.Equal(c.RawIssuer, issuer) && c.SerialNumber.Cmp(serial) == 0 {
			s.signer = c
			break
		}
	}
	if s.signer == nil {
		return fmt.Errorf("%w: it does not carry the signer's certificate", ErrMalformed)
	}
	h, err := readHash(&si)
	if err != nil {
		return err
	}
	s.signerHash = h
	var attrs cryptobyte.String
	if !si.ReadASN1(&attrs, tagContext0) {
		return fmt.Errorf("%w: it has no signed attributes", ErrMalformed)
	}
	var b cryptobyte.Builder
	b.AddASN1(cbasn1.SET, func(b *cryptobyte.Builder) { b.AddBytes(attrs) })
	s.attrs = b.BytesOrPanic()
	if err := s.readAttributes(attrs); err != nil {
		return err
	}
	var sig cryptobyte.String
	if !si.SkipASN1(cbasn1.SEQUENCE) || !si.ReadASN1(&sig, cbasn1.OCTET_STRING) {
		return ErrMalformed
	}
	s.sig = sig
	if si.PeekASN1Tag(tagContext1) {
		var unsigned cryptobyte.String
		if !si.ReadASN1(&unsigned, tagContext1) {
			return ErrMalformed
		}
		return s.readUnsigned(unsigned)
	}
	return nil
}

// readAttributes reads the content type and message digest the signature covers.
func (s *signedData) readAttributes(attrs cryptobyte.String) error {
	for !attrs.Empty() {
		var attr, values cryptobyte.String
		var oid asn1.ObjectIdentifier
		if !attrs.ReadASN1(&attr, cbasn1.SEQUENCE) || !attr.ReadASN1ObjectIdentifier(&oid) || !attr.ReadASN1(&values, cbasn1.SET) {
			return ErrMalformed
		}
		switch {
		case oid.Equal(oidContentType):
			if s.contentType != nil || !values.ReadASN1ObjectIdentifier(&s.contentType) {
				return ErrMalformed
			}
		case oid.Equal(oidMessageDigest):
			var d cryptobyte.String
			if s.msgDigest != nil || !values.ReadASN1(&d, cbasn1.OCTET_STRING) {
				return ErrMalformed
			}
			s.msgDigest = d
		}
	}
	if s.contentType == nil || s.msgDigest == nil {
		return fmt.Errorf("%w: the signed attributes lack the content type or message digest", ErrMalformed)
	}
	return nil
}

// readUnsigned notes a timestamp and nested signatures.
func (s *signedData) readUnsigned(attrs cryptobyte.String) error {
	for !attrs.Empty() {
		var attr, values cryptobyte.String
		var oid asn1.ObjectIdentifier
		if !attrs.ReadASN1(&attr, cbasn1.SEQUENCE) || !attr.ReadASN1ObjectIdentifier(&oid) || !attr.ReadASN1(&values, cbasn1.SET) {
			return ErrMalformed
		}
		switch {
		case oid.Equal(oidCounterSignature), oid.Equal(oidRFC3161Timestamp):
			s.timestamped = true
		case oid.Equal(oidNestedSignature):
			for !values.Empty() {
				if !values.SkipASN1(cbasn1.SEQUENCE) {
					return ErrMalformed
				}
				s.nested++
			}
		}
	}
	return nil
}

// verify checks the signed attributes against the content and the signature
// against the signer's certificate.
func (s *signedData) verify() error {
	if !s.contentType.Equal(oidSpcIndirectData) {
		return ErrMalformed
	}
	h := s.signerHash.New()
	h.Write(s.spc)
	if !bytes.Equal(h.Sum(nil), s.msgDigest) {
		return ErrBadSignature
	}
	h = s.signerHash.New()
	h.Write(s.attrs)
	sum := h.Sum(nil)
	switch pub := s.signer.PublicKey.(type) {
	case *rsa.PublicKey:
		if rsa.VerifyPKCS1v15(pub, s.signerHash, sum, s.sig) != nil {
			return ErrBadSignature
		}
	case *ecdsa.PublicKey:
		if !ecdsa.VerifyASN1(pub, sum, s.sig) {
			return ErrBadSignature
		}
	default:
		return fmt.Errorf("%w: the signer's key type", ErrUnsupported)
	}
	if !forCode(s.signer) {
		return ErrNotForCode
	}
	return nil
}

// forCode says whether a certificate may sign code: it names code signing
// among its extended key usages, or limits them to none.
func forCode(c *x509.Certificate) bool {
	if len(c.ExtKeyUsage) == 0 && len(c.UnknownExtKeyUsage) == 0 {
		return true
	}
	for _, u := range c.ExtKeyUsage {
		if u == x509.ExtKeyUsageCodeSigning || u == x509.ExtKeyUsageAny {
			return true
		}
	}
	return false
}
