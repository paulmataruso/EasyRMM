package client

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"

	"github.com/paulmataruso/easyrmm/internal/agentproto"
	"github.com/paulmataruso/easyrmm/internal/qaticket"
)

// wireServer answers the Quick Assist and escrow paths with canned JSON and
// records what it was sent; fail makes every answer a 409 error.
type wireServer struct {
	mu   sync.Mutex
	fail bool
	got  map[string]string
}

func (s *wireServer) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	b, _ := io.ReadAll(r.Body)
	s.mu.Lock()
	s.got[r.URL.Path] = string(b)
	fail := s.fail
	s.mu.Unlock()
	if fail {
		w.WriteHeader(http.StatusConflict)
		_, _ = io.WriteString(w, `{"error":{"code":"nope","message":"refused"}}`)
		return
	}
	switch r.URL.Path {
	case qaticket.PathEnroll:
		_, _ = io.WriteString(w, `{"jobKey":"k","deviceId":"d1","sessionId":"s1","heartbeatSeconds":7,"organization":"Org"}`)
	case qaticket.PathStatus:
		_, _ = io.WriteString(w, `{"state":"active","install":"offered","offer":{"organization":"Org","site":"Main"}}`)
	case qaticket.PathInstall:
		_, _ = io.WriteString(w, `{"token":"ert_x"}`)
	case agentproto.PathEscrowVolumes:
		_, _ = io.WriteString(w, `{"need":[{"volumeId":"C:"}]}`)
	case agentproto.PathEscrow:
		_, _ = io.WriteString(w, `{"state":"pending","again":true}`)
	default:
		_, _ = io.WriteString(w, `{}`)
	}
}

func TestQuickAssistAndEscrowCalls(t *testing.T) {
	s := &wireServer{got: map[string]string{}}
	srv := httptest.NewServer(s)
	t.Cleanup(srv.Close)
	c, err := New(Options{Server: srv.URL, Version: "9.9"})
	if err != nil {
		t.Fatal(err)
	}
	ctx := context.Background()

	// Unsigned enroll works before an identity exists; signed calls refuse.
	en, err := c.QAEnroll(ctx, QAEnrollRequest{Ticket: "t", Consent: true, Facts: QAFacts{Hostname: "h"}})
	if err != nil || en.SessionID != "s1" || en.HeartbeatSeconds != 7 || en.DeviceID != "d1" {
		t.Fatalf("enroll: %+v, %v", en, err)
	}
	if !strings.Contains(s.got[qaticket.PathEnroll], `"consent":true`) {
		t.Errorf("enroll body: %s", s.got[qaticket.PathEnroll])
	}
	if _, err := c.QAStatus(ctx); err == nil || !strings.Contains(err.Error(), "not enrolled") {
		t.Errorf("status before identity: %v", err)
	}

	_, key, _ := ed25519.GenerateKey(rand.Reader)
	c.SetIdentity("d1", key)
	st, err := c.QAStatus(ctx)
	if err != nil || st.State != "active" || st.Offer == nil || st.Offer.Site != "Main" {
		t.Fatalf("status: %+v, %v", st, err)
	}
	if err := c.QAMesh(ctx, "node//x"); err != nil || !strings.Contains(s.got[qaticket.PathMesh], "node//x") {
		t.Errorf("mesh: %v %s", err, s.got[qaticket.PathMesh])
	}
	tok, err := c.QAInstall(ctx, true)
	if err != nil || tok != "ert_x" || !strings.Contains(s.got[qaticket.PathInstall], `"accept":true`) {
		t.Errorf("install: %q, %v", tok, err)
	}
	if err := c.QAConverted(ctx); err != nil {
		t.Errorf("converted: %v", err)
	}
	rep := &QACleanup{Result: "clean", Checks: []QACheck{{Name: "folder", OK: true}}}
	if err := c.QAEnd(ctx, "done", rep); err != nil || !strings.Contains(s.got[qaticket.PathEnd], `"reason":"done"`) {
		t.Errorf("end: %v %s", err, s.got[qaticket.PathEnd])
	}

	vols, err := c.EscrowVolumes(ctx, agentproto.EscrowVolumesReport{})
	if err != nil || len(vols.Need) != 1 || vols.Need[0].VolumeID != "C:" {
		t.Errorf("escrow volumes: %+v, %v", vols, err)
	}
	ans, err := c.EscrowUpload(ctx, agentproto.EscrowRecord{VolumeID: "C:"})
	if err != nil || ans.State != "pending" || !ans.Again {
		t.Errorf("escrow upload: %+v, %v", ans, err)
	}
	var sent agentproto.EscrowRecord
	if json.Unmarshal([]byte(s.got[agentproto.PathEscrow]), &sent) != nil || sent.VolumeID != "C:" {
		t.Errorf("escrow body: %s", s.got[agentproto.PathEscrow])
	}

	// The server refuses every call: each returns its error.
	s.mu.Lock()
	s.fail = true
	s.mu.Unlock()
	if _, err := c.QAEnroll(ctx, QAEnrollRequest{}); Code(err) != "nope" {
		t.Errorf("enroll refused: %v", err)
	}
	if _, err := c.QAStatus(ctx); Code(err) != "nope" {
		t.Errorf("status refused: %v", err)
	}
	if err := c.QAMesh(ctx, "n"); err == nil {
		t.Error("mesh refused: no error")
	}
	if _, err := c.QAInstall(ctx, false); Code(err) != "nope" {
		t.Errorf("install refused: %v", err)
	}
	if err := c.QAConverted(ctx); err == nil {
		t.Error("converted refused: no error")
	}
	if err := c.QAEnd(ctx, "x", nil); err == nil {
		t.Error("end refused: no error")
	}
	if _, err := c.EscrowVolumes(ctx, agentproto.EscrowVolumesReport{}); Code(err) != "nope" {
		t.Errorf("escrow volumes refused: %v", err)
	}
	if _, err := c.EscrowUpload(ctx, agentproto.EscrowRecord{}); Code(err) != "nope" {
		t.Errorf("escrow upload refused: %v", err)
	}
}
