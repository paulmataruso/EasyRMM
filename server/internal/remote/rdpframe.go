package remote

import (
	"context"
	"crypto/rand"
	"encoding/binary"
	"encoding/json"
	"fmt"
	"sort"
	"strings"
	"unicode/utf8"

	"github.com/google/uuid"
)

// Saved RDP credentials (ADR-0079). The browser's first RDP message names a
// saved credential by id; the gateway replaces the id with the credential
// before the message reaches MeshCentral, so the browser never holds the
// password and MeshCentral never stores one.

// CredentialUse describes one start of an RDP session that asks for a saved
// credential. Every field but CredentialID comes from the relay's
// authenticated grant, never from the message the browser sent.
type CredentialUse struct {
	CredentialID uuid.UUID
	Session      uuid.UUID
	Grant        uuid.UUID
	User         uuid.UUID
	Organization uuid.UUID
	Site         uuid.UUID
	Device       uuid.UUID
	ClientIP     string
}

// OpenedCredential is a saved credential ready to be written into the first
// RDP message. Password is a byte slice the caller zeroes with Zero.
type OpenedCredential struct {
	Domain   string
	Username string
	Password []byte
}

// Zero overwrites the password.
func (o *OpenedCredential) Zero() {
	if o != nil {
		clear(o.Password)
	}
}

// CredentialOpener decides whether a saved credential may be used for a
// session and opens it. It checks the permissions, the step-up and the
// organization scope, and audits the use or the refusal; an error refuses
// the session.
type CredentialOpener interface {
	OpenRDPCredential(ctx context.Context, use CredentialUse) (*OpenedCredential, error)
}

// SetCredentialOpener turns on saved RDP credentials. Without it, a first
// message that names one is refused.
func (g *Gateway) SetCredentialOpener(o CredentialOpener) { g.creds = o }

// rdpGrant is what the gateway knows about the authenticated RDP session.
type rdpGrant struct {
	Grant, User, Organization, Site, Device uuid.UUID
	ClientIP                                string
}

// useSavedKey is the option the console sets to name a saved credential.
const useSavedKey = "useSavedCredential"

// rdpTransform returns the transform for the first message of the browser's
// RDP relay (the one rdpCheck has just admitted). It forces MeshCentral's own
// credential saving and server-side credentials off on every first message
// and, when the message names a saved credential, writes the credential into
// it. The replacement is returned as the message's new payload; the guard
// rebuilds the frame around it.
func (g *Gateway) rdpTransform(ctx context.Context, session uuid.UUID) func([]byte) ([]byte, error) {
	return func(msg []byte) ([]byte, error) {
		return rewriteInfos(msg, func(id uuid.UUID, node string) (*OpenedCredential, error) {
			if g.creds == nil || g.rdpGrantFor == nil {
				return nil, refused("saved RDP credentials are not available")
			}
			grant, err := g.rdpGrantFor(ctx, session, node)
			if err != nil {
				return nil, refused("finding the RDP grant failed: %v", err)
			}
			cred, err := g.creds.OpenRDPCredential(ctx, CredentialUse{
				CredentialID: id, Session: session, Grant: grant.Grant, User: grant.User,
				Organization: grant.Organization, Site: grant.Site, Device: grant.Device, ClientIP: grant.ClientIP,
			})
			if err != nil {
				return nil, refused("saved RDP credential refused: %v", err)
			}
			return cred, nil
		})
	}
}

// rewriteInfos is the first RDP message with MeshCentral's credential saving
// forced off and, if it names a saved credential, that credential written in.
// It builds the saved password into a byte slice it sizes up front (so no
// copy is left behind by a growing slice) and never converts it to a string.
// The returned payload is the caller's to zero once it is sent.
func rewriteInfos(msg []byte, open func(id uuid.UUID, node string) (*OpenedCredential, error)) ([]byte, error) {
	var m []json.RawMessage
	if err := json.Unmarshal(msg, &m); err != nil || len(m) < 2 {
		return nil, refused("RDP connection request without details")
	}
	var obj map[string]json.RawMessage
	if err := json.Unmarshal(m[1], &obj); err != nil || obj == nil {
		return nil, refused("RDP connection request without details")
	}
	opts := map[string]json.RawMessage{}
	if raw, ok := obj["options"]; ok && string(raw) != "null" {
		if err := json.Unmarshal(raw, &opts); err != nil || opts == nil {
			return nil, refused("RDP connection request with options that are not an object")
		}
	}
	var savedID uuid.UUID
	if raw, ok := opts[useSavedKey]; ok {
		var s string
		if err := json.Unmarshal(raw, &s); err != nil {
			return nil, refused("saved RDP credential id that is not a string")
		}
		id, err := uuid.Parse(s)
		if err != nil {
			return nil, refused("saved RDP credential id that is not valid")
		}
		savedID = id
		delete(opts, useSavedKey)
	}
	opts["savepass"] = json.RawMessage("false")
	opts["useServerCreds"] = json.RawMessage("false")
	delete(obj, "options")

	var cred *OpenedCredential
	if savedID != uuid.Nil {
		var infos struct {
			IP string `json:"ip"`
		}
		if err := json.Unmarshal(m[1], &infos); err != nil {
			return nil, refused("RDP connection request without details")
		}
		if !strings.HasPrefix(infos.IP, "node/") {
			return nil, refused("saved RDP credential for an address that is not a device")
		}
		node, err := normalizeNodeID(infos.IP)
		if err != nil {
			return nil, err
		}
		if cred, err = open(savedID, node); err != nil {
			return nil, err
		}
		defer cred.Zero()
		delete(obj, "domain")
		delete(obj, "username")
		delete(obj, "password")
	}
	optBytes, err := json.Marshal(opts)
	if err != nil {
		return nil, err
	}
	keys := make([]string, 0, len(obj))
	size := len(optBytes) + 64
	for k, v := range obj {
		keys = append(keys, k)
		size += len(k) + len(v) + 8
	}
	sort.Strings(keys)
	for _, r := range m[2:] {
		size += len(r) + 1
	}
	var domain, user []byte
	if cred != nil {
		domain, _ = json.Marshal(cred.Domain)
		user, _ = json.Marshal(cred.Username)
		size += len(domain) + len(user) + 6*len(cred.Password) + 64
	}
	out := make([]byte, 0, size)
	out = append(out, '[')
	out = append(out, m[0]...)
	out = append(out, ',', '{')
	for _, k := range keys {
		kb, _ := json.Marshal(k)
		out = append(out, kb...)
		out = append(out, ':')
		out = append(out, obj[k]...)
		out = append(out, ',')
	}
	if cred != nil {
		out = append(out, `"domain":`...)
		out = append(out, domain...)
		out = append(out, `,"username":`...)
		out = append(out, user...)
		out = append(out, `,"password":`...)
		out = appendJSONString(out, cred.Password)
		out = append(out, ',')
	}
	out = append(out, `"options":`...)
	out = append(out, optBytes...)
	out = append(out, '}')
	for _, r := range m[2:] {
		out = append(out, ',')
		out = append(out, r...)
	}
	out = append(out, ']')
	if len(out) > maxControlMessage {
		clear(out)
		return nil, refused("control message over %d bytes", maxControlMessage)
	}
	return out, nil
}

// appendJSONString appends s as a JSON string, escaping what JSON requires
// and replacing bytes that are not UTF-8 with U+FFFD, without converting s to
// a string.
func appendJSONString(dst, s []byte) []byte {
	const hex = "0123456789abcdef"
	dst = append(dst, '"')
	for i := 0; i < len(s); {
		c := s[i]
		switch {
		case c == '"' || c == '\\':
			dst = append(dst, '\\', c)
			i++
		case c < 0x20:
			dst = append(dst, '\\', 'u', '0', '0', hex[c>>4], hex[c&0xf])
			i++
		case c < utf8.RuneSelf:
			dst = append(dst, c)
			i++
		default:
			r, n := utf8.DecodeRune(s[i:])
			if r == utf8.RuneError && n == 1 {
				dst = append(dst, `�`...)
			} else {
				dst = append(dst, s[i:i+n]...)
			}
			i += n
		}
	}
	return append(dst, '"')
}

// buildTextFrame returns payload as one WebSocket text frame from a client:
// FIN set, no reserved bits, the shortest length form that fits, and a fresh
// random mask key.
func buildTextFrame(payload []byte) ([]byte, error) {
	n := len(payload)
	if n > maxControlMessage {
		return nil, refused("control message over %d bytes", maxControlMessage)
	}
	var head [14]byte
	head[0] = 0x80 | 0x1
	hl := 2
	switch {
	case n <= 125:
		head[1] = 0x80 | byte(n)
	case n <= 0xffff:
		head[1] = 0x80 | 126
		binary.BigEndian.PutUint16(head[2:4], uint16(n))
		hl = 4
	default:
		head[1] = 0x80 | 127
		binary.BigEndian.PutUint64(head[2:10], uint64(n))
		hl = 10
	}
	if _, err := rand.Read(head[hl : hl+4]); err != nil {
		return nil, fmt.Errorf("mask key: %w", err)
	}
	key := head[hl : hl+4]
	out := make([]byte, hl+4+n)
	copy(out, head[:hl+4])
	for i, c := range payload {
		out[hl+4+i] = c ^ key[i&3]
	}
	return out, nil
}
