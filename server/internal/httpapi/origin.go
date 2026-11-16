package httpapi

import (
	"context"
	"net/http"
)

// Origin is the address a request reached the server at (ADR-0016): the
// public URL, or one of the server's IP addresses.
type Origin struct {
	// Console is the console origin, e.g. https://rmm.example.com.
	Console string
	// Mesh is the MeshCentral origin remote sessions from this console
	// origin use; empty without remote access.
	Mesh string
	// Pin is the public-key pin of the certificate served on this origin
	// when it comes from the server's own certificate authority.
	Pin string
	// KeyPin is the same key's pin for PowerShell, the hex SHA-256 of the
	// public key (pki.Authority.KeyPin).
	KeyPin string
}

type originKey struct{}

// WithOrigin records the origin a request arrived at.
func WithOrigin(r *http.Request, o Origin) *http.Request {
	return r.WithContext(context.WithValue(r.Context(), originKey{}, o))
}

// OriginOf returns the origin a request arrived at, if recorded.
func OriginOf(r *http.Request) (Origin, bool) {
	o, ok := r.Context().Value(originKey{}).(Origin)
	return o, ok
}
