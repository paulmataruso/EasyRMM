// Package enrollfile reads install.conf, the enrollment file a package or an
// administrator leaves for the agent (ADR-0056): the server, a deployment
// token and, optionally, the server's own certificate authority.
//
// Only a file an administrator made, and only administrators can read, is
// read. The file is opened first and checked on the open file, so that it
// cannot be swapped between the check and the read. Anything else is
// refused and left unread, with the reason.
package enrollfile

import (
	"bufio"
	"bytes"
	"crypto/sha256"
	"crypto/x509"
	"encoding/base64"
	"encoding/hex"
	"encoding/pem"
	"errors"
	"fmt"
	"strings"
	"time"
)

// File is what install.conf holds.
type File struct {
	Server string
	Token  string
	// CA is the server's own certificate authority, base64 DER on one line;
	// "" for none.
	CA string
}

// MaxSize bounds what is read: the file holds three short lines.
const MaxSize = 64 << 10

// Settle is how long the file must have been unchanged before it is read, so
// that a file still being written, or not yet given its mode, is not taken.
const Settle = 5 * time.Second

// ErrSettling means the file changed less than Settle ago; try again.
var ErrSettling = errors.New("the enrollment file changed a moment ago")

// Refusal is a file the agent will not read, and why. The file is left
// unread and untouched.
type Refusal struct {
	Path   string
	Reason string
	// Readable says that someone other than administrators could read it
	// (its mode or access list lets them), so that a token in it may be known
	// to them: the agent says to revoke the token.
	Readable bool
}

func (r *Refusal) Error() string {
	s := r.Path + " is not used: " + r.Reason
	if r.Readable {
		s += "; others could read it, so revoke the token it holds and make the file as the guide says (mode 0600 from the start)"
	}
	return s
}

// Policy says what to read and what to check.
type Policy struct {
	// Path is install.conf.
	Path string
	// Top is the highest folder whose owner and permissions are checked: the
	// folders from Top down to the file's must be an administrator's and
	// writable by no one else.
	Top string
	// UID is the owner the file and its folders must have on Unix; 0 is root.
	UID uint32
	// Now is the time; nil for the real one.
	Now func() time.Time
}

func (p Policy) now() time.Time {
	if p.Now != nil {
		return p.Now()
	}
	return time.Now()
}

// Fingerprint changes when the file changes: its content, size, owner, mode
// or access list, or its modification or change time, so that a chmod alone
// counts.
type Fingerprint string

// raw is what a platform's open and check found.
type raw struct {
	data []byte
	// meta is the file's size, owner, mode or access list, and times.
	meta string
	// changed is the later of the modification and change times.
	changed time.Time
}

// Read opens, checks and reads the file. It returns fs.ErrNotExist (test with
// errors.Is) when there is none, ErrSettling while it is too new, a *Refusal
// when it fails the check, and another error when it cannot be read or
// understood. The fingerprint is returned with every answer that read the
// file, including a bad one, so that a caller can wait for it to change.
func Read(p Policy) (File, Fingerprint, error) {
	r, err := open(p)
	if err != nil {
		return File{}, "", err
	}
	sum := sha256.Sum256(r.data)
	fp := Fingerprint(hex.EncodeToString(sum[:]) + "|" + r.meta)
	if p.now().Sub(r.changed) < Settle {
		return File{}, fp, ErrSettling
	}
	f, err := Parse(r.data)
	return f, fp, err
}

// Parse reads the INI text of install.conf:
//
//	[enrollment]
//	server=https://rmm.example.com
//	token=ert_...
//	ca=MIIC...
//
// Lines may be blank or start with # or ;. Nothing else is accepted: another
// section or key, or a key given twice, is an error, since a typo must not be
// taken for a setting.
func Parse(b []byte) (File, error) {
	if len(b) > MaxSize {
		return File{}, errors.New("the enrollment file is too large")
	}
	b = bytes.TrimPrefix(b, []byte("\xef\xbb\xbf"))
	var f File
	seen := map[string]bool{}
	inSection := false
	sc := bufio.NewScanner(bytes.NewReader(b))
	sc.Buffer(make([]byte, 0, 4096), MaxSize)
	for n := 1; sc.Scan(); n++ {
		line := strings.TrimSpace(sc.Text())
		switch {
		case line == "" || line[0] == '#' || line[0] == ';':
			continue
		case line[0] == '[':
			if line != "[enrollment]" {
				return File{}, fmt.Errorf("line %d: only the [enrollment] section is read", n)
			}
			inSection = true
			continue
		}
		if !inSection {
			return File{}, fmt.Errorf("line %d: a setting before [enrollment]", n)
		}
		k, v, ok := strings.Cut(line, "=")
		k, v = strings.ToLower(strings.TrimSpace(k)), strings.TrimSpace(v)
		if !ok {
			return File{}, fmt.Errorf("line %d: expected key=value", n)
		}
		if seen[k] {
			return File{}, fmt.Errorf("line %d: %s is given twice", n, k)
		}
		seen[k] = true
		switch k {
		case "server":
			f.Server = v
		case "token":
			f.Token = v
		case "ca":
			f.CA = v
		default:
			return File{}, fmt.Errorf("line %d: unknown setting %q", n, k)
		}
	}
	if err := sc.Err(); err != nil {
		return File{}, err
	}
	if f.CA != "" {
		if _, err := f.CAPEM(); err != nil {
			return File{}, err
		}
	}
	return f, nil
}

// CAPEM is the certificate authority as a PEM file, as the agent keeps it.
func (f File) CAPEM() ([]byte, error) {
	if f.CA == "" {
		return nil, nil
	}
	der, err := base64.StdEncoding.DecodeString(f.CA)
	if err != nil {
		return nil, errors.New("ca is not base64")
	}
	if _, err := x509.ParseCertificate(der); err != nil {
		return nil, errors.New("ca is not a certificate (base64 DER)")
	}
	return pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der}), nil
}

// Marshal is the file's text.
func (f File) Marshal() []byte {
	var b strings.Builder
	b.WriteString("[enrollment]\n")
	if f.Server != "" {
		b.WriteString("server=" + f.Server + "\n")
	}
	if f.Token != "" {
		b.WriteString("token=" + f.Token + "\n")
	}
	if f.CA != "" {
		b.WriteString("ca=" + f.CA + "\n")
	}
	return []byte(b.String())
}

// FromPEM turns one PEM certificate into the file's ca value. It refuses a
// file with no certificate, or with more than one, which the file cannot hold.
func FromPEM(b []byte) (string, error) {
	var der []byte
	for {
		var blk *pem.Block
		blk, b = pem.Decode(b)
		if blk == nil {
			break
		}
		if blk.Type != "CERTIFICATE" {
			continue
		}
		if der != nil {
			return "", errors.New("the file holds more than one certificate; install.conf holds one")
		}
		der = blk.Bytes
	}
	if der == nil {
		return "", errors.New("no certificate in the file")
	}
	if _, err := x509.ParseCertificate(der); err != nil {
		return "", errors.New("the file's certificate is not valid")
	}
	return base64.StdEncoding.EncodeToString(der), nil
}
