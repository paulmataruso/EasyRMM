// Package releasetest makes what a build publishes, for tests: manifests,
// and attestations made the way GitHub's are, with
// a Sigstore instance made for the test: sigstore-go's virtual Sigstore
// (its testing certificate authority) for the transparency log, and a
// certificate authority and certificate transparency log of the test's own,
// because the virtual one's certificates carry neither GitHub's extensions
// nor a certificate timestamp. The signatures, the log's promise and proof,
// and the certificate timestamp are real; only the root of trust differs.
// Nothing here is used outside tests: the updater's release build trusts
// Sigstore's public-good instance only.
package releasetest

import (
	"context"
	"crypto"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/asn1"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"math/big"
	"net/url"
	"time"

	ct "github.com/google/certificate-transparency-go"
	cttls "github.com/google/certificate-transparency-go/tls"
	"github.com/google/certificate-transparency-go/x509util"
	"github.com/secure-systems-lab/go-securesystemslib/dsse"
	protobundle "github.com/sigstore/protobuf-specs/gen/pb-go/bundle/v1"
	protocommon "github.com/sigstore/protobuf-specs/gen/pb-go/common/v1"
	protodsse "github.com/sigstore/protobuf-specs/gen/pb-go/dsse"
	protorekor "github.com/sigstore/protobuf-specs/gen/pb-go/rekor/v1"
	"github.com/sigstore/sigstore-go/pkg/fulcio/certificate"
	"github.com/sigstore/sigstore-go/pkg/root"
	"github.com/sigstore/sigstore-go/pkg/testing/ca"
	"github.com/sigstore/sigstore-go/pkg/tlog"
	"github.com/sigstore/sigstore/pkg/signature"
	sigdsse "github.com/sigstore/sigstore/pkg/signature/dsse"
	"google.golang.org/protobuf/encoding/protojson"
	"google.golang.org/protobuf/proto"

	"github.com/paulmataruso/easyrmm/updater/internal/release"
)

// Sigstore is a Sigstore instance of the test's own.
type Sigstore struct {
	virtual   *ca.VirtualSigstore
	rootCert  *x509.Certificate
	interCert *x509.Certificate
	interKey  *ecdsa.PrivateKey
	ctKey     *ecdsa.PrivateKey
	trusted   *root.TrustedRoot
}

// New makes an instance: keys and certificates generated now.
func New() (*Sigstore, error) {
	virtual, err := ca.NewVirtualSigstore()
	if err != nil {
		return nil, err
	}
	rootCert, rootKey, err := ca.GenerateRootCa()
	if err != nil {
		return nil, err
	}
	interCert, interKey, err := ca.GenerateFulcioIntermediate(rootCert, rootKey)
	if err != nil {
		return nil, err
	}
	ctKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return nil, err
	}
	s := &Sigstore{virtual: virtual, rootCert: rootCert, interCert: interCert, interKey: interKey, ctKey: ctKey}
	// Open-ended from an hour ago, so that what the test attests verifies
	// however long the test runs: verification checks the certificates at
	// the time the log recorded, as Sigstore's own instance's do.
	since := time.Now().Add(-time.Hour)
	ctID, err := keyID(ctKey.Public())
	if err != nil {
		return nil, err
	}
	ctLogs := map[string]*root.TransparencyLog{hex.EncodeToString(ctID): {
		BaseURL: "https://ctfe.sigstore.test", ID: ctID, ValidityPeriodStart: since,
		HashFunc: crypto.SHA256, PublicKey: ctKey.Public(), SignatureHashFunc: crypto.SHA256,
	}}
	rekorLogs := map[string]*root.TransparencyLog{}
	for id, l := range virtual.RekorLogs() {
		// The virtual instance gives its log's ID as the hexadecimal text's
		// bytes, which is not what trusted_root.json holds.
		raw, err := hex.DecodeString(id)
		if err != nil {
			return nil, err
		}
		c := *l
		c.ID, c.ValidityPeriodStart, c.ValidityPeriodEnd = raw, since, time.Time{}
		rekorLogs[id] = &c
	}
	fulcio := &root.FulcioCertificateAuthority{
		Root: rootCert, Intermediates: []*x509.Certificate{interCert},
		ValidityPeriodStart: since, URI: "https://fulcio.sigstore.test",
	}
	s.trusted, err = root.NewTrustedRoot(root.TrustedRootMediaType01, []root.CertificateAuthority{fulcio}, ctLogs, nil, rekorLogs)
	if err != nil {
		return nil, err
	}
	return s, nil
}

// TrustedRoot is the instance's root of trust, for a verifier.
func (s *Sigstore) TrustedRoot() *root.TrustedRoot { return s.trusted }

// TrustedRootJSON is the root of trust as Sigstore's trusted_root.json
// writes it, for an updater built for tests on another machine.
func (s *Sigstore) TrustedRootJSON() ([]byte, error) { return s.trusted.MarshalJSON() }

// Claims are what a certificate says about the workflow that asked for it,
// as Fulcio writes GitHub Actions' token into it.
type Claims struct {
	// SAN is the workflow's identity, https://github.com/<repo>/<file>@<ref>.
	SAN               string
	Issuer            string
	BuildConfigURI    string
	SourceRef         string
	Trigger           string
	RunnerEnvironment string
	RepositoryID      string
	Commit            string
}

// For is what the right workflow's certificate says for a version: the
// release workflow at its tag, or CI on main for an edge build.
func For(v release.Version, commit string) Claims {
	w := release.WorkflowFor(v)
	return Claims{
		SAN: w.URI(), Issuer: release.Issuer, BuildConfigURI: w.URI(), SourceRef: w.Ref,
		Trigger: release.Trigger, RunnerEnvironment: release.RunnerEnvironment,
		RepositoryID: release.RepositoryID, Commit: commit,
	}
}

// File is a file an attestation names.
type File struct {
	Name     string
	Contents []byte
}

// Attest attests files as actions/attest-build-provenance does (an edge
// build's attestation names its manifest, a release's every file of the
// release), with a certificate saying c, and returns the Sigstore bundle
// as JSON.
func (s *Sigstore) Attest(c Claims, files ...File) ([]byte, error) {
	leaf, leafKey, err := s.leaf(c)
	if err != nil {
		return nil, err
	}
	subjects := make([]map[string]any, len(files))
	for i, f := range files {
		digest := sha256.Sum256(f.Contents)
		subjects[i] = map[string]any{"name": f.Name, "digest": map[string]string{"sha256": hex.EncodeToString(digest[:])}}
	}
	statement, err := json.Marshal(map[string]any{
		"_type":         "https://in-toto.io/Statement/v1",
		"subject":       subjects,
		"predicateType": "https://slsa.dev/provenance/v1",
		"predicate":     map[string]any{"buildDefinition": map[string]any{"buildType": "https://actions.github.io/buildtypes/workflow/v1"}},
	})
	if err != nil {
		return nil, err
	}
	signer, err := signature.LoadECDSASignerVerifier(leafKey, crypto.SHA256)
	if err != nil {
		return nil, err
	}
	envSigner, err := dsse.NewEnvelopeSigner(&sigdsse.SignerAdapter{SignatureSigner: signer, Pub: &leafKey.PublicKey})
	if err != nil {
		return nil, err
	}
	env, err := envSigner.SignPayload(context.Background(), "application/vnd.in-toto+json", statement)
	if err != nil {
		return nil, err
	}
	sig, err := base64.StdEncoding.DecodeString(env.Signatures[0].Sig)
	if err != nil {
		return nil, err
	}
	integrated := time.Now()
	entry, err := s.virtual.GenerateTlogEntry(leaf, env, sig, integrated.Unix(), true)
	if err != nil {
		return nil, err
	}
	tle, ok := proto.Clone(entry.TransparencyLogEntry()).(*protorekor.TransparencyLogEntry)
	if !ok {
		return nil, fmt.Errorf("unexpected transparency log entry type")
	}
	logID, err := s.virtual.RekorLogID()
	if err != nil {
		return nil, err
	}
	set, err := s.virtual.RekorSignPayload(tlog.RekorPayload{
		Body:           base64.StdEncoding.EncodeToString(tle.GetCanonicalizedBody()),
		IntegratedTime: tle.GetIntegratedTime(),
		LogIndex:       tle.GetLogIndex(),
		LogID:          logID,
	})
	if err != nil {
		return nil, err
	}
	tle.KindVersion = &protorekor.KindVersion{Kind: "dsse", Version: "0.0.1"}
	tle.InclusionPromise = &protorekor.InclusionPromise{SignedEntryTimestamp: set}
	payload, err := base64.StdEncoding.DecodeString(env.Payload)
	if err != nil {
		return nil, err
	}
	b := &protobundle.Bundle{
		MediaType: "application/vnd.dev.sigstore.bundle.v0.3+json",
		VerificationMaterial: &protobundle.VerificationMaterial{
			Content:     &protobundle.VerificationMaterial_Certificate{Certificate: &protocommon.X509Certificate{RawBytes: leaf.Raw}},
			TlogEntries: []*protorekor.TransparencyLogEntry{tle},
		},
		Content: &protobundle.Bundle_DsseEnvelope{DsseEnvelope: &protodsse.Envelope{
			Payload: payload, PayloadType: env.PayloadType,
			Signatures: []*protodsse.Signature{{Sig: sig}},
		}},
	}
	return protojson.Marshal(b)
}

// leaf issues a certificate for c from the instance's authority, valid for
// ten minutes as Fulcio's are, with a certificate timestamp from the
// instance's certificate transparency log embedded.
func (s *Sigstore) leaf(c Claims) (*x509.Certificate, *ecdsa.PrivateKey, error) {
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return nil, nil, err
	}
	san, err := url.Parse(c.SAN)
	if err != nil {
		return nil, nil, err
	}
	serial, err := rand.Int(rand.Reader, new(big.Int).Lsh(big.NewInt(1), 128))
	if err != nil {
		return nil, nil, err
	}
	// Fulcio's certificates carry the deprecated issuer extension too.
	exts := []pkix.Extension{{Id: certificate.OIDIssuer, Value: []byte(c.Issuer)}} //nolint:staticcheck // as above
	for _, e := range []struct {
		id    asn1.ObjectIdentifier
		value string
	}{
		{certificate.OIDIssuerV2, c.Issuer},
		{certificate.OIDBuildSignerURI, c.SAN},
		{certificate.OIDRunnerEnvironment, c.RunnerEnvironment},
		{certificate.OIDSourceRepositoryURI, "https://github.com/" + release.Repository},
		{certificate.OIDSourceRepositoryDigest, c.Commit},
		{certificate.OIDSourceRepositoryRef, c.SourceRef},
		{certificate.OIDSourceRepositoryIdentifier, c.RepositoryID},
		{certificate.OIDBuildConfigURI, c.BuildConfigURI},
		{certificate.OIDBuildTrigger, c.Trigger},
	} {
		v, err := asn1.MarshalWithParams(e.value, "utf8")
		if err != nil {
			return nil, nil, err
		}
		exts = append(exts, pkix.Extension{Id: e.id, Value: v})
	}
	now := time.Now()
	tmpl := &x509.Certificate{
		SerialNumber:    serial,
		NotBefore:       now.Add(-time.Minute),
		NotAfter:        now.Add(10 * time.Minute),
		KeyUsage:        x509.KeyUsageDigitalSignature,
		ExtKeyUsage:     []x509.ExtKeyUsage{x509.ExtKeyUsageCodeSigning},
		URIs:            []*url.URL{san},
		ExtraExtensions: exts,
	}
	// The certificate transparency log signs the certificate without its
	// list of timestamps, which is then added last: the same certificate
	// with the list removed is what a verifier checks the timestamp against.
	precert, err := s.issue(tmpl, &key.PublicKey)
	if err != nil {
		return nil, nil, err
	}
	list, err := s.sct(precert.RawTBSCertificate, now)
	if err != nil {
		return nil, nil, err
	}
	tmpl.ExtraExtensions = append(exts, pkix.Extension{Id: asn1.ObjectIdentifier{1, 3, 6, 1, 4, 1, 11129, 2, 4, 2}, Value: list})
	cert, err := s.issue(tmpl, &key.PublicKey)
	if err != nil {
		return nil, nil, err
	}
	return cert, key, nil
}

func (s *Sigstore) issue(tmpl *x509.Certificate, pub crypto.PublicKey) (*x509.Certificate, error) {
	der, err := x509.CreateCertificate(rand.Reader, tmpl, s.interCert, pub, s.interKey)
	if err != nil {
		return nil, err
	}
	return x509.ParseCertificate(der)
}

// sct is the value of the certificate extension listing one signed
// certificate timestamp (RFC 6962 3.3) for the certificate whose
// TBSCertificate, without that extension, is tbs.
func (s *Sigstore) sct(tbs []byte, at time.Time) ([]byte, error) {
	id, err := keyID(s.ctKey.Public())
	if err != nil {
		return nil, err
	}
	sct := ct.SignedCertificateTimestamp{SCTVersion: ct.V1, Timestamp: uint64(at.UnixMilli())} //nolint:gosec // a time after 1970
	copy(sct.LogID.KeyID[:], id)
	leaf := ct.MerkleTreeLeaf{
		Version: ct.V1, LeafType: ct.TimestampedEntryLeafType,
		TimestampedEntry: &ct.TimestampedEntry{
			EntryType: ct.PrecertLogEntryType, Timestamp: sct.Timestamp,
			PrecertEntry: &ct.PreCert{IssuerKeyHash: sha256.Sum256(s.interCert.RawSubjectPublicKeyInfo), TBSCertificate: tbs},
		},
	}
	input, err := ct.SerializeSCTSignatureInput(sct, ct.LogEntry{Leaf: leaf})
	if err != nil {
		return nil, err
	}
	h := sha256.Sum256(input)
	sig, err := ecdsa.SignASN1(rand.Reader, s.ctKey, h[:])
	if err != nil {
		return nil, err
	}
	sct.Signature = ct.DigitallySigned{
		Algorithm: cttls.SignatureAndHashAlgorithm{Hash: cttls.SHA256, Signature: cttls.ECDSA},
		Signature: sig,
	}
	list, err := x509util.MarshalSCTsIntoSCTList([]*ct.SignedCertificateTimestamp{&sct})
	if err != nil {
		return nil, err
	}
	raw, err := cttls.Marshal(*list)
	if err != nil {
		return nil, err
	}
	return asn1.Marshal(raw)
}

// keyID is a log's ID: the SHA-256 of its public key.
func keyID(pub crypto.PublicKey) ([]byte, error) {
	der, err := x509.MarshalPKIXPublicKey(pub)
	if err != nil {
		return nil, err
	}
	sum := sha256.Sum256(der)
	return sum[:], nil
}
