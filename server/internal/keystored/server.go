package keystored

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"errors"
	"io"
	"log/slog"
	"net"
	"os"
	"slices"
	"sync"
	"time"

	"github.com/paulmataruso/easyrmm/internal/escrowcrypto"
	"github.com/paulmataruso/easyrmm/server/internal/keystore"
)

// Server answers the keystore's two sockets.
//
// The service socket is in a directory the server container also mounts; the
// kernel's peer credentials (SO_PEERCRED) must name one of ServiceUIDs. The
// admin socket is inside the keystore container only, and its peer must be
// the keystore's own user: only a person who runs a command in the container
// (docker compose exec) reaches init, unseal and verify-recovery, so a
// compromised console or server process can neither feed nor capture a
// passphrase.
type Server struct {
	KS          *Keystore
	ServiceUIDs []uint32
	AdminUID    uint32
	Log         *slog.Logger

	// Timeouts, shortened by tests.
	ReadTimeout time.Duration
}

// Serve accepts connections on both listeners until ctx ends.
func (s *Server) Serve(ctx context.Context, service, admin net.Listener) error {
	if s.ReadTimeout == 0 {
		s.ReadTimeout = 10 * time.Second
	}
	if s.Log == nil {
		s.Log = slog.New(slog.DiscardHandler)
	}
	var wg sync.WaitGroup
	errs := make(chan error, 2)
	for _, l := range []struct {
		ln    net.Listener
		admin bool
	}{{service, false}, {admin, true}} {
		if l.ln == nil {
			continue
		}
		wg.Go(func() { errs <- s.accept(ctx, l.ln, l.admin) })
	}
	<-ctx.Done()
	if service != nil {
		_ = service.Close()
	}
	if admin != nil {
		_ = admin.Close()
	}
	wg.Wait()
	return nil
}

func (s *Server) accept(ctx context.Context, ln net.Listener, admin bool) error {
	slots := make(chan struct{}, 16)
	for {
		c, err := ln.Accept()
		if err != nil {
			if ctx.Err() != nil || errors.Is(err, net.ErrClosed) {
				return nil //nolint:nilerr // the listener closed because the server is stopping
			}
			return err
		}
		select {
		case slots <- struct{}{}:
		default:
			_ = c.Close() // busy: the caller retries
			continue
		}
		go func() {
			defer func() { <-slots }()
			s.serveConn(c, admin)
		}()
	}
}

func (s *Server) allowed(uid uint32, admin bool) bool {
	if admin {
		return uid == s.AdminUID
	}
	return slices.Contains(s.ServiceUIDs, uid)
}

func (s *Server) serveConn(c net.Conn, admin bool) {
	defer func() { _ = c.Close() }()
	uid, err := peerUID(c)
	if err != nil || !s.allowed(uid, admin) {
		// Not a word to a peer that is not allowed.
		s.Log.Warn("keystore: refused a connection from a user that is not allowed", "admin_socket", admin)
		return
	}
	_ = c.SetDeadline(time.Now().Add(s.ReadTimeout))
	var req keystore.Request
	dec := json.NewDecoder(io.LimitReader(c, keystore.MaxMessage))
	if err := dec.Decode(&req); err != nil {
		writeResp(c, keystore.Response{Code: keystore.CodeBadRequest, Error: "the request is not valid JSON"})
		return
	}
	defer func() {
		zero(req.Passphrase)
		zero(req.Code)
	}()
	// An answer may take long: Argon2id at init and unseal.
	_ = c.SetWriteDeadline(time.Now().Add(2 * time.Minute))
	resp := s.handle(&req, admin)
	s.Log.Info("keystore: request", "op", req.Op, "request_id", req.ID, "ok", resp.OK, "code", resp.Code)
	s.journal(&req, &resp)
	writeResp(c, resp)
}

// journal writes the log line of an operation that is not a read (reads write
// their own before they answer) and is not a status poll. The line is also
// the host's journal's, through the process log.
func (s *Server) journal(req *keystore.Request, resp *keystore.Response) {
	switch req.Op {
	case keystore.OpStatus, keystore.OpLog, keystore.OpReadEscrow:
		return
	}
	res := "ok"
	if !resp.OK {
		res = resp.Code
	}
	org := req.Org
	if org == "" && req.Context != nil {
		org = req.Context.Org
	}
	s.KS.note(keystore.LogEntry{Op: req.Op, Org: org, RequestID: req.ID, Result: res})
}

// writeResp sends the answer. A key is never given to the JSON encoder, whose
// buffers are pooled and kept: it is encoded by hand into a slice this
// function zeroes, and the key itself is zeroed once written.
func writeResp(c net.Conn, r keystore.Response) {
	if len(r.Plaintext) == 0 {
		_ = json.NewEncoder(c).Encode(r)
		return
	}
	defer zero(r.Plaintext)
	b := make([]byte, 0, 32+base64.StdEncoding.EncodedLen(len(r.Plaintext)))
	defer func() { zero(b[:cap(b)]) }()
	b = append(b, `{"ok":true,"plaintext":"`...)
	b = base64.StdEncoding.AppendEncode(b, r.Plaintext)
	b = append(b, '"', '}', '\n')
	_, _ = c.Write(b)
}

func errResp(err error) keystore.Response {
	var e *Error
	if errors.As(err, &e) {
		return keystore.Response{Code: e.Code, Error: e.Msg}
	}
	return keystore.Response{Code: keystore.CodeInternal, Error: err.Error()}
}

// handle runs one request. admin says which socket it came on.
func (s *Server) handle(req *keystore.Request, admin bool) keystore.Response {
	switch req.Op {
	case keystore.OpStatus:
		st := s.KS.Status()
		return keystore.Response{OK: true, Status: &st}
	case keystore.OpCreateOrgKey:
		if admin {
			return keystore.Response{Code: keystore.CodeBadRequest, Error: "not an admin operation"}
		}
		pub, wrapped, ver, err := s.KS.CreateOrgKey(req.Org, req.KeyID, req.Purpose)
		if err != nil {
			return errResp(err)
		}
		return keystore.Response{OK: true, PublicKey: pub, WrappedPrivate: wrapped, KEKVersion: ver}
	case keystore.OpReadEscrow:
		if admin || req.Context == nil {
			return keystore.Response{Code: keystore.CodeBadRequest, Error: "not a valid request"}
		}
		c := req.Context
		pt, err := s.KS.ReadEscrow(ReadRequest{
			RequestID: req.ID, Record: req.Record, Kind: req.Kind, Wrapped: req.WrappedPrivate, Enc: req.Enc, Ciphertext: req.Ciphertext, Fingerprint: req.Fingerprint,
			Context: escrowcrypto.Context{Org: c.Org, Device: c.Device, Volume: c.Volume, Protector: c.Protector, OrgKey: c.OrgKey},
		})
		if err != nil {
			return errResp(err)
		}
		return keystore.Response{OK: true, Plaintext: pt}
	case keystore.OpRewrapOrgKey:
		if admin {
			return keystore.Response{Code: keystore.CodeBadRequest, Error: "not an admin operation"}
		}
		nw, ver, err := s.KS.RewrapOrgKey(req.Org, req.KeyID, req.Purpose, req.WrappedPrivate)
		if err != nil {
			return errResp(err)
		}
		return keystore.Response{OK: true, WrappedPrivate: nw, KEKVersion: ver}
	case keystore.OpResealEscrow:
		if admin || req.Context == nil || req.NewContext == nil {
			return keystore.Response{Code: keystore.CodeBadRequest, Error: "not a valid request"}
		}
		o, n := req.Context, req.NewContext
		enc, ct, err := s.KS.ResealEscrow(ResealRequest{
			RequestID: req.ID, Record: req.Record, Kind: req.Kind, OldWrapped: req.WrappedPrivate, NewPublic: req.NewPublic,
			Old: escrowcrypto.Context{Org: o.Org, Device: o.Device, Volume: o.Volume, Protector: o.Protector, OrgKey: o.OrgKey},
			New: escrowcrypto.Context{Org: n.Org, Device: n.Device, Volume: n.Volume, Protector: n.Protector, OrgKey: n.OrgKey},
			Enc: req.Enc, Ciphertext: req.Ciphertext, Fingerprint: req.Fingerprint,
		})
		if err != nil {
			return errResp(err)
		}
		return keystore.Response{OK: true, Enc: enc, Ciphertext: ct}
	case keystore.OpLog:
		if admin {
			return keystore.Response{Code: keystore.CodeBadRequest, Error: "not an admin operation"}
		}
		prev, entries, err := s.KS.LogSince(req.Since, req.Limit)
		if err != nil {
			return errResp(err)
		}
		return keystore.Response{OK: true, Entries: entries, LogPrev: prev}
	case keystore.OpVerifyEscrow:
		if admin || req.Context == nil {
			return keystore.Response{Code: keystore.CodeBadRequest, Error: "not a valid request"}
		}
		c := req.Context
		result, err := s.KS.VerifyEscrow(req.WrappedPrivate, escrowcrypto.Context{
			Org: c.Org, Device: c.Device, Volume: c.Volume, Protector: c.Protector, OrgKey: c.OrgKey,
		}, req.Enc, req.Ciphertext, req.Fingerprint, req.Kind)
		if err != nil {
			return errResp(err)
		}
		return keystore.Response{OK: true, Result: result}
	}
	if !admin {
		return keystore.Response{Code: keystore.CodeDenied, Error: "this operation is at the host only"}
	}
	switch req.Op {
	case keystore.OpInit:
		code, bf, err := s.KS.Init(req.Mode, req.Passphrase)
		if err != nil {
			return errResp(err)
		}
		defer zero(code)
		return keystore.Response{OK: true, RecoveryCode: string(code), BundlePath: bf, Version: 1}
	case keystore.OpUnseal:
		if err := s.KS.Unseal(req.Passphrase); err != nil {
			return errResp(err)
		}
		st := s.KS.Status()
		return keystore.Response{OK: true, Status: &st}
	case keystore.OpVerifyRecovery:
		v, err := s.KS.VerifyRecovery(req.Bundle, req.Code)
		if err != nil {
			return errResp(err)
		}
		return keystore.Response{OK: true, Version: v}
	case keystore.OpNewVersion:
		v, bf, err := s.KS.NewVersion()
		if err != nil {
			return errResp(err)
		}
		return keystore.Response{OK: true, Version: v, BundlePath: bf}
	}
	return keystore.Response{Code: keystore.CodeBadRequest, Error: "unknown operation"}
}

// Listen makes a Unix socket at path with the mode and removes a stale one.
func Listen(path string, mode os.FileMode) (net.Listener, error) {
	_ = os.Remove(path)
	ln, err := (&net.ListenConfig{}).Listen(context.Background(), "unix", path)
	if err != nil {
		return nil, err
	}
	if err := os.Chmod(path, mode); err != nil {
		_ = ln.Close()
		return nil, err
	}
	return ln, nil
}
