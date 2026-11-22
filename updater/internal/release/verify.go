package release

import (
	"crypto/sha256"
	"fmt"

	"github.com/sigstore/sigstore-go/pkg/bundle"
	"github.com/sigstore/sigstore-go/pkg/fulcio/certificate"
	"github.com/sigstore/sigstore-go/pkg/root"
	"github.com/sigstore/sigstore-go/pkg/verify"
)

// The repository whose workflows the updater trusts. Its numeric ID is
// fixed when the repository is created and survives a rename or a transfer;
// a fork or a repository made again under the same name has another.
const (
	Repository   = "paulmataruso/EasyRMM"
	RepositoryID = "1458774020"
)

// What every attestation the updater accepts was made by: GitHub Actions'
// OpenID Connect issuer, on a runner GitHub hosts, for a push.
const (
	Issuer            = "https://token.actions.githubusercontent.com"
	RunnerEnvironment = "github-hosted"
	Trigger           = "push"
)

// MaxSigstoreBundleBytes bounds an attestation's Sigstore bundle; a real
// one is about 10 KiB.
const MaxSigstoreBundleBytes = 1 << 20

// Workflow is the workflow and ref an attestation must come from: the
// release workflow at the release's tag, or, for an edge build, CI's last
// job on main.
type Workflow struct {
	// File is the workflow file (.github/workflows/release.yml).
	File string
	// Ref is the Git ref it ran for (refs/tags/easyrmm-v1.2.3).
	Ref string
}

// WorkflowFor is the workflow a version's attestation must come from.
func WorkflowFor(v Version) Workflow {
	if v.Kind() == KindEdge {
		return Workflow{File: ".github/workflows/ci.yml", Ref: "refs/heads/main"}
	}
	return Workflow{File: ".github/workflows/release.yml", Ref: "refs/tags/" + v.Tag()}
}

// URI is the workflow's identity as Fulcio writes it, both as the
// certificate's subject alternative name and as its build configuration:
// https://github.com/<repository>/<file>@<ref>.
func (w Workflow) URI() string {
	return "https://github.com/" + Repository + "/" + w.File + "@" + w.Ref
}

// Verifier checks manifests against their attestations.
type Verifier struct {
	v *verify.Verifier
}

// NewVerifier verifies against trusted material: Sigstore's public-good
// instance in a release build, a test's own instance in tests. Every
// attestation must carry a certificate timestamp from a certificate
// transparency log and an entry in a transparency log, whose time is when
// the certificate must have been valid; that is what GitHub's attestations
// carry.
func NewVerifier(trusted root.TrustedMaterial) (*Verifier, error) {
	v, err := verify.NewVerifier(trusted,
		verify.WithSignedCertificateTimestamps(1),
		verify.WithTransparencyLog(1),
		verify.WithObserverTimestamps(1),
		verify.WithoutStatementPredicate())
	if err != nil {
		return nil, fmt.Errorf("sigstore verifier: %w", err)
	}
	return &Verifier{v: v}, nil
}

// Verify checks a manifest against its attestation's Sigstore bundle and
// returns it, now trusted, when everything matches:
//
//   - the attestation is for this manifest's SHA-256, signed with a
//     certificate the trusted material's authority issued and logged;
//   - the certificate's issuer is GitHub Actions', its repository this
//     one by numeric ID, its runner GitHub-hosted and its trigger a push;
//   - its identity and its build configuration are both the workflow the
//     manifest's version must come from, and its source ref that
//     workflow's ref (for a release, the tag of the manifest's version);
//   - its source commit is the manifest's commit;
//   - and the channel admits the version: an edge build only the edge
//     channel.
//
// The version is the manifest's alone; the caller compares it with the one
// it asked for.
func (v *Verifier) Verify(manifestJSON, sigstoreBundleJSON []byte, channel Channel) (*Manifest, error) {
	m, err := ParseManifest(manifestJSON)
	if err != nil {
		return nil, err
	}
	if !channel.Admits(m.Version.Kind()) {
		return nil, fmt.Errorf("%s is a %s, which the %s channel does not take", m.Version, m.Version.Kind(), channel)
	}
	if len(sigstoreBundleJSON) > MaxSigstoreBundleBytes {
		return nil, fmt.Errorf("the attestation is %d bytes, more than %d", len(sigstoreBundleJSON), MaxSigstoreBundleBytes)
	}
	var b bundle.Bundle
	if err := b.UnmarshalJSON(sigstoreBundleJSON); err != nil {
		return nil, fmt.Errorf("the attestation is not a Sigstore bundle: %w", err)
	}
	w := WorkflowFor(m.Version)
	san, err := verify.NewSANMatcher(w.URI(), "")
	if err != nil {
		return nil, err
	}
	iss, err := verify.NewIssuerMatcher(Issuer, "")
	if err != nil {
		return nil, err
	}
	id, err := verify.NewCertificateIdentity(san, iss, certificate.Extensions{
		RunnerEnvironment:          RunnerEnvironment,
		SourceRepositoryDigest:     m.Commit,
		SourceRepositoryRef:        w.Ref,
		SourceRepositoryIdentifier: RepositoryID,
		BuildConfigURI:             w.URI(),
		BuildTrigger:               Trigger,
	})
	if err != nil {
		return nil, err
	}
	digest := sha256.Sum256(manifestJSON)
	policy := verify.NewPolicy(verify.WithArtifactDigest("sha256", digest[:]), verify.WithCertificateIdentity(id))
	if _, err := v.v.Verify(&b, policy); err != nil {
		return nil, fmt.Errorf("the manifest of %s is not attested by %s: %w", m.Version, w.URI(), err)
	}
	return m, nil
}
