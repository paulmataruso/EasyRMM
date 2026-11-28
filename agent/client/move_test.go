package client

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/paulmataruso/easyrmm/internal/agentproto"
)

// addressServer answers PathAddress as the server does, signing with job, and
// PathMove with 204; mutate changes the answer before it is sent.
func addressServer(t *testing.T, job ed25519.PrivateKey, mutate func(a agentproto.Auth, ans *agentproto.AddressAnswer)) (*httptest.Server, *[]agentproto.MoveReport) {
	t.Helper()
	var reports []agentproto.MoveReport
	srv := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		a, err := agentproto.Parse(r.Header.Get("Authorization"))
		if err != nil {
			w.WriteHeader(http.StatusUnauthorized)
			return
		}
		switch r.URL.Path {
		case agentproto.PathAddress:
			var in agentproto.AddressRequest
			_ = json.NewDecoder(r.Body).Decode(&in)
			ans := agentproto.SignAddress(job, a, in.Address)
			if mutate != nil {
				mutate(a, &ans)
			}
			_ = json.NewEncoder(w).Encode(ans)
		case agentproto.PathMove:
			var in agentproto.MoveReport
			_ = json.NewDecoder(r.Body).Decode(&in)
			reports = append(reports, in)
			w.WriteHeader(http.StatusNoContent)
		default:
			w.WriteHeader(http.StatusNotFound)
		}
	}))
	t.Cleanup(srv.Close)
	return srv, &reports
}

func addressClient(t *testing.T, srv *httptest.Server) *Client {
	t.Helper()
	c, err := New(Options{Server: srv.URL, Transport: srv.Client().Transport, NoRedirect: true})
	if err != nil {
		t.Fatal(err)
	}
	_, key, _ := ed25519.GenerateKey(rand.Reader)
	c.SetIdentity("dev-1", key)
	return c
}

func TestConfirmAddressAcceptsOnlyAConfirmationByATrustedKeyForThisExchange(t *testing.T) {
	pub, job, _ := ed25519.GenerateKey(rand.Reader)
	otherPub, otherKey, _ := ed25519.GenerateKey(rand.Reader)
	keys := agentproto.Keys{pub}

	srv, _ := addressServer(t, job, nil)
	c := addressClient(t, srv)
	if err := c.ConfirmAddress(context.Background(), keys); err != nil {
		t.Fatalf("a good confirmation: %v", err)
	}

	for name, c := range map[string]struct {
		mutate func(a agentproto.Auth, ans *agentproto.AddressAnswer)
		keys   agentproto.Keys
		want   error
	}{
		"signed by a key the agent does not trust": {func(a agentproto.Auth, ans *agentproto.AddressAnswer) {
			*ans = agentproto.SignAddress(otherKey, a, ans.Address)
		}, keys, agentproto.ErrAddressSignature},
		"a trusted key, another nonce": {func(a agentproto.Auth, ans *agentproto.AddressAnswer) {
			a.Nonce += "x"
			*ans = agentproto.SignAddress(job, a, ans.Address)
		}, keys, agentproto.ErrAddressSignature},
		"another device": {func(a agentproto.Auth, ans *agentproto.AddressAnswer) {
			a.Device = "dev-2"
			*ans = agentproto.SignAddress(job, a, ans.Address)
		}, keys, agentproto.ErrAddressSignature},
		"another address": {func(a agentproto.Auth, ans *agentproto.AddressAnswer) {
			*ans = agentproto.SignAddress(job, a, "https://other.example.com")
		}, keys, agentproto.ErrAddressMismatch},
		"unsigned":                               {func(_ agentproto.Auth, ans *agentproto.AddressAnswer) { ans.Signature = "" }, keys, agentproto.ErrAddressUnsigned},
		"signed by a key the agent trusts later": {nil, agentproto.Keys{otherPub}, agentproto.ErrAddressSignature},
	} {
		srv, _ := addressServer(t, job, c.mutate)
		cl := addressClient(t, srv)
		if err := cl.ConfirmAddress(context.Background(), c.keys); !errors.Is(err, c.want) {
			t.Errorf("%s: %v, want %v", name, err, c.want)
		}
	}

	// No pinned key checks nothing.
	if err := c.ConfirmAddress(context.Background(), nil); err == nil {
		t.Error("checked with no key")
	}
}

func TestConfirmAddressFailsOnRedirectsMissingRoutesAndPlainHTTP(t *testing.T) {
	pub, job, _ := ed25519.GenerateKey(rand.Reader)
	keys := agentproto.Keys{pub}

	// A redirect is not followed, and is not a confirmation.
	target, _ := addressServer(t, job, nil)
	redirect := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		http.Redirect(w, r, target.URL+r.URL.Path, http.StatusTemporaryRedirect)
	}))
	t.Cleanup(redirect.Close)
	c := addressClient(t, redirect)
	var e *Error
	if err := c.ConfirmAddress(context.Background(), keys); !errors.As(err, &e) || e.Status != http.StatusTemporaryRedirect {
		t.Errorf("redirect: %v", err)
	}

	// A server from before the route answers 404: a failed check.
	old := httptest.NewTLSServer(http.NotFoundHandler())
	t.Cleanup(old.Close)
	if err := addressClient(t, old).ConfirmAddress(context.Background(), keys); !errors.As(err, &e) || e.Status != http.StatusNotFound {
		t.Errorf("404: %v", err)
	}

	// An answer that is not JSON.
	junk := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) { _, _ = w.Write([]byte("<html>")) }))
	t.Cleanup(junk.Close)
	if err := addressClient(t, junk).ConfirmAddress(context.Background(), keys); err == nil {
		t.Error("an HTML answer was a confirmation")
	}

	// Plain http, loopback included, is never confirmed or even asked.
	plain := httptest.NewServer(http.NotFoundHandler())
	t.Cleanup(plain.Close)
	pc, err := New(Options{Server: plain.URL, NoRedirect: true})
	if err != nil {
		t.Fatal(err)
	}
	_, key, _ := ed25519.GenerateKey(rand.Reader)
	pc.SetIdentity("dev-1", key)
	if err := pc.ConfirmAddress(context.Background(), keys); err == nil {
		t.Error("plain http was confirmed")
	}

	// A client that was never enrolled cannot ask.
	srv, _ := addressServer(t, job, nil)
	anon, _ := New(Options{Server: srv.URL, Transport: srv.Client().Transport})
	if err := anon.ConfirmAddress(context.Background(), keys); err == nil {
		t.Error("an unenrolled client asked")
	}
}

func TestMovedSendsTheReportSignedAndSurfacesA404(t *testing.T) {
	_, job, _ := ed25519.GenerateKey(rand.Reader)
	srv, reports := addressServer(t, job, nil)
	c := addressClient(t, srv)
	rep := agentproto.MoveReport{Kind: agentproto.MoveSetServer, From: "https://a.example.com", To: "https://b.example.com", Moved: true}
	if err := c.Moved(context.Background(), rep); err != nil {
		t.Fatal(err)
	}
	if len(*reports) != 1 || (*reports)[0] != rep {
		t.Errorf("the server got %+v", *reports)
	}

	old := httptest.NewTLSServer(http.NotFoundHandler())
	t.Cleanup(old.Close)
	var e *Error
	if err := addressClient(t, old).Moved(context.Background(), rep); !errors.As(err, &e) || e.Status != http.StatusNotFound {
		t.Errorf("an older server: %v", err)
	}
}
