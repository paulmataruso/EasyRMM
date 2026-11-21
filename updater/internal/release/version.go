// Package release decides what the updater on the host trusts (ADR-0052):
// the versions it accepts and how they sort, the channels, the manifest a
// build publishes, and the Sigstore attestation that manifest must carry.
package release

import (
	"fmt"
	"regexp"
	"strconv"
	"strings"
)

// Kind is what a version names: a full release, a release candidate, or a
// build of main.
type Kind int

// The kinds of version, in the order the channels admit them.
const (
	KindRelease Kind = iota + 1
	KindCandidate
	KindEdge
)

func (k Kind) String() string {
	switch k {
	case KindRelease:
		return "release"
	case KindCandidate:
		return "release candidate"
	case KindEdge:
		return "edge build"
	}
	return "unknown"
}

// Version is one of the four forms ADR-0052 allows, written as the server
// reports it, with its "v":
//
//	v1.2.3                     a release
//	v1.2.3-rc.4                a release candidate
//	v1.2.3-rc.4.edge.412.1     a build of main after a release candidate
//	v1.2.4-edge.415.1          a build of main after a release (its patch raised)
//
// Anything else is not a version the updater installs.
type Version struct {
	raw                 string
	major, minor, patch uint64
	// pre is the pre-release part split at its dots; empty for a release.
	pre []string
	// rc, run and attempt are the numbers of those parts, 0 when absent.
	rc, run, attempt uint64
	kind             Kind
}

// num is a number without leading zeros, of at most nine digits so that it
// never overflows and a version stays short.
const num = `(0|[1-9][0-9]{0,8})`

// pos is a number from 1.
const pos = `([1-9][0-9]{0,8})`

var versionRE = regexp.MustCompile(`^v` + num + `\.` + num + `\.` + num +
	`(?:-(?:rc\.` + pos + `(?:\.edge\.` + pos + `\.` + pos + `)?|edge\.` + pos + `\.` + pos + `))?$`)

// ParseVersion parses one of the four forms, and nothing else.
func ParseVersion(s string) (Version, error) {
	m := versionRE.FindStringSubmatch(s)
	if m == nil {
		return Version{}, fmt.Errorf("%q is not a version the updater installs (v1.2.3, v1.2.3-rc.4, v1.2.3-rc.4.edge.412.1 or v1.2.4-edge.415.1)", s)
	}
	n := func(i int) uint64 {
		if m[i] == "" {
			return 0
		}
		v, _ := strconv.ParseUint(m[i], 10, 64) // nine digits at most: never fails
		return v
	}
	v := Version{raw: s, major: n(1), minor: n(2), patch: n(3)}
	switch {
	case m[4] != "" && m[5] != "":
		v.kind, v.rc, v.run, v.attempt = KindEdge, n(4), n(5), n(6)
	case m[4] != "":
		v.kind, v.rc = KindCandidate, n(4)
	case m[7] != "":
		v.kind, v.run, v.attempt = KindEdge, n(7), n(8)
	default:
		v.kind = KindRelease
	}
	if i := strings.IndexByte(s, '-'); i >= 0 {
		v.pre = strings.Split(s[i+1:], ".")
	}
	return v, nil
}

// MustParseVersion is ParseVersion for versions written in code and tests.
func MustParseVersion(s string) Version {
	v, err := ParseVersion(s)
	if err != nil {
		panic(err)
	}
	return v
}

func (v Version) String() string { return v.raw }

// IsZero reports whether v is the zero Version, which names nothing.
func (v Version) IsZero() bool { return v.raw == "" }

// Kind reports what v names.
func (v Version) Kind() Kind { return v.kind }

// Tag is the Git tag of a release or release candidate (easyrmm-v1.2.3),
// and "" for an edge build, which has none.
func (v Version) Tag() string {
	if v.kind == KindEdge {
		return ""
	}
	return "easyrmm-" + v.raw
}

// ImageTag is the version without its "v", as image tags and .env's
// EASYRMM_VERSION write it.
func (v Version) ImageTag() string { return strings.TrimPrefix(v.raw, "v") }

// Compare orders versions as semantic versioning does: -1 when v sorts
// before w, 0 when they are the same, 1 when after. A pre-release sorts
// before its release, numbers compare as numbers and sort before words,
// and a longer pre-release sorts after a shorter one it starts with, so
// v1.0.0-rc.4 < v1.0.0-rc.4.edge.412.1 < v1.0.0-rc.5 and
// v1.0.0 < v1.0.1-edge.415.1 < v1.0.1-rc.1 < v1.0.1.
func (v Version) Compare(w Version) int {
	for _, c := range [][2]uint64{{v.major, w.major}, {v.minor, w.minor}, {v.patch, w.patch}} {
		if c[0] != c[1] {
			return cmpUint(c[0], c[1])
		}
	}
	switch {
	case len(v.pre) == 0 && len(w.pre) == 0:
		return 0
	case len(v.pre) == 0:
		return 1
	case len(w.pre) == 0:
		return -1
	}
	for i := 0; i < len(v.pre) && i < len(w.pre); i++ {
		if c := compareIdent(v.pre[i], w.pre[i]); c != 0 {
			return c
		}
	}
	return cmpUint(uint64(len(v.pre)), uint64(len(w.pre)))
}

func compareIdent(a, b string) int {
	an, aErr := strconv.ParseUint(a, 10, 64)
	bn, bErr := strconv.ParseUint(b, 10, 64)
	switch {
	case aErr == nil && bErr == nil:
		return cmpUint(an, bn)
	case aErr == nil:
		return -1
	case bErr == nil:
		return 1
	}
	return strings.Compare(a, b)
}

func cmpUint(a, b uint64) int {
	switch {
	case a < b:
		return -1
	case a > b:
		return 1
	}
	return 0
}

// Channel is which versions an install takes.
type Channel string

// The channels: stable takes full releases, pre-release also release
// candidates, edge also builds of main.
const (
	ChannelStable     Channel = "stable"
	ChannelPreRelease Channel = "pre-release"
	ChannelEdge       Channel = "edge"
)

// ParseChannel accepts the three channels by name.
func ParseChannel(s string) (Channel, error) {
	switch c := Channel(s); c {
	case ChannelStable, ChannelPreRelease, ChannelEdge:
		return c, nil
	}
	return "", fmt.Errorf("%q is not a channel (stable, pre-release or edge)", s)
}

// Admits reports whether the channel takes versions of kind k.
func (c Channel) Admits(k Kind) bool {
	switch c {
	case ChannelStable:
		return k == KindRelease
	case ChannelPreRelease:
		return k == KindRelease || k == KindCandidate
	case ChannelEdge:
		return k == KindRelease || k == KindCandidate || k == KindEdge
	}
	return false
}

// Newest returns the highest of the versions the channel admits, and false
// when it admits none of them.
func (c Channel) Newest(versions []Version) (Version, bool) {
	var best Version
	for _, v := range versions {
		if c.Admits(v.kind) && (best.IsZero() || v.Compare(best) > 0) {
			best = v
		}
	}
	return best, !best.IsZero()
}
