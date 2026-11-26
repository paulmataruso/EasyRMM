//go:build integration

package remote

import (
	"bytes"
	"context"
	"crypto/rand"
	"net"
	"net/http"
	"net/url"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/coder/websocket"
	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"

	"github.com/paulmataruso/easyrmm/server/internal/database"
	"github.com/paulmataruso/easyrmm/server/internal/devices"
	"github.com/paulmataruso/easyrmm/server/internal/rbac"
	"github.com/paulmataruso/easyrmm/server/internal/rdpcreds"
	"github.com/paulmataruso/easyrmm/server/internal/secrets"
)

// rdpOpener adapts the saved-credentials service to the gateway, as the
// server's wiring does.
type rdpOpener struct{ svc *rdpcreds.Service }

func (o rdpOpener) OpenRDPCredential(ctx context.Context, u CredentialUse) (*OpenedCredential, error) {
	c, err := o.svc.OpenForSession(ctx, rdpcreds.Use(u))
	if err != nil {
		return nil, err
	}
	return &OpenedCredential{Domain: c.Domain, Username: c.Username, Password: c.Password}, nil
}

const savedRDPPassword = "Saved-only P@ss 7731"

// A saved RDP credential, end to end: the browser sends only its id, the
// gateway writes the credential into the first message, and MeshCentral
// takes the rebuilt frame and connects to the device's RDP port. MeshCentral
// is told not to save, and its database never holds the password. Without a
// step-up nothing is sent.
func TestSavedRDPCredentialEndToEnd(t *testing.T) {
	image := os.Getenv("EASYRMM_TEST_AGENT_IMAGE")
	if image == "" {
		t.Fatal("EASYRMM_TEST_AGENT_IMAGE is not set (a glibc Linux image for the test agent; see the Makefile)")
	}
	r := newRig(t)
	acme := r.org("Acme")
	hq := r.site(acme.ID, "HQ")
	techID, tech := r.user("Tess Tech", rbac.Assignment{Role: rbac.RoleTechnician, OrganizationID: acme.ID, SiteID: hq.ID})
	r.reconcile()

	key := make([]byte, secrets.KeySize)
	_, _ = rand.Read(key)
	sealer, err := secrets.NewSealer(secrets.Key{ID: "t1", Raw: key})
	if err != nil {
		t.Fatal(err)
	}
	creds := rdpcreds.New(r.db, r.audit, sealer, func(context.Context, uuid.UUID) (*rbac.Principal, error) { return tech.Principal, nil })

	upstream, _ := url.Parse(r.env.URL)
	g, err := NewGateway(r.svc, GatewayConfig{Upstream: upstream, Secure: true, CacheTTL: 200 * time.Millisecond}, r.log)
	if err != nil {
		t.Fatal(err)
	}
	g.SetCredentialOpener(rdpOpener{creds})
	r.serveGateway(g)
	go r.svc.Run(r.ctx)

	dir := r.agentFiles(r.meshOfSite(hq.ID))
	name := "easyrmm-testagent-" + uuid.NewString()[:8]
	docker(t, "run", "-d", "--name", name, "--network", "host",
		"--add-host", r.env.Hostname+":127.0.0.1",
		"--user", "65534:65534", "--read-only", "--tmpfs", "/tmp", "--cap-drop", "ALL",
		"--security-opt", "no-new-privileges", "-v", dir+":/agent", "-w", "/agent",
		image, "./meshagent", "connect")
	t.Cleanup(func() {
		if t.Failed() {
			t.Logf("agent output:\n%s", docker(t, "logs", "--tail", "50", name))
		}
		_, _ = exec.Command("docker", "rm", "-f", name).CombinedOutput()
	})
	var dev *devices.Device
	r.waitFor(2*time.Minute, "the agent's device to come online", func() bool {
		list, err := r.dev.List(r.ctx, tech, devices.Query{Status: "online"})
		if err == nil && len(list) == 1 {
			dev = list[0]
		}
		return dev != nil
	})
	// The agent is a Linux one; saved credentials are for Windows computers,
	// and the relay does not care which the device is.
	r.exec(`UPDATE devices SET platform = 'windows' WHERE id = $1`, dev.ID)

	cr, err := creds.Save(r.ctx, tech, dev.ID, rdpcreds.SaveInput{Label: "Admin", Domain: "TESTDOM", Username: "svc-saved", Password: []byte(savedRDPPassword)})
	if err != nil {
		t.Fatal(err)
	}

	// The device's RDP port, played by the test: it keeps the first bytes
	// MeshCentral's RDP client sends.
	rdpServer, err := net.Listen("tcp4", "127.0.0.1:3389")
	if err != nil {
		t.Fatalf("the RDP check plays an RDP server on 127.0.0.1:3389: %v", err)
	}
	defer func() { _ = rdpServer.Close() }()
	arrived := make(chan []byte, 4)
	go func() {
		for {
			c, err := rdpServer.Accept()
			if err != nil {
				return
			}
			go func() {
				defer func() { _ = c.Close() }()
				_ = c.SetReadDeadline(time.Now().Add(30 * time.Second))
				buf := make([]byte, 512)
				n, err := c.Read(buf)
				if err == nil || n > 0 {
					arrived <- buf[:n]
				}
			}()
		}
	}()
	// rdp opens a session of the person and sends the connection request
	// with the saved credential's id and MeshCentral's saving asked for.
	rdp := func(session uuid.UUID, wait time.Duration) (closed bool, head []byte) {
		t.Helper()
		l, err := r.svc.StartSession(r.ctx, tech, session, dev.ID, KindRDP)
		if err != nil {
			t.Fatal(err)
		}
		b := r.browser()
		r.open(b, l)
		ws, err := r.dial(b, "/mstscrelay.ashx")
		if err != nil {
			t.Fatal(err)
		}
		defer func() { _ = ws.CloseNow() }()
		infos := `["infos",{"ip":"` + dev.MeshNodeID + `","port":3389,"screen":{"width":1024,"height":768},` +
			`"domain":"","username":"","password":"","options":{"useSavedCredential":"` + cr.ID.String() + `","savepass":true,"useServerCreds":true},"locale":"en-US"}]`
		wctx, wcancel := context.WithTimeout(r.ctx, wait)
		defer wcancel()
		if err := ws.Write(wctx, websocket.MessageText, []byte(infos)); err != nil {
			t.Fatal(err)
		}
		readErr := make(chan error, 1)
		go func() {
			for {
				if _, _, err := ws.Read(wctx); err != nil {
					readErr <- err
					return
				}
			}
		}()
		select {
		case head = <-arrived:
		case err := <-readErr:
			closed = err != nil && wctx.Err() == nil
		case <-wctx.Done():
		}
		return closed, head
	}

	// Not stepped up: the relay closes, nothing reaches the device, and the
	// refusal is audited.
	if closed, head := rdp(r.session(techID), 20*time.Second); !closed || head != nil {
		t.Errorf("without a step-up: closed %v, device got %x", closed, head)
	}
	if r.count(`SELECT count(*) FROM audit_log WHERE action = 'rdp_credential.use_denied'`) != 1 {
		t.Error("the refusal was not audited")
	}

	// Stepped up: MeshCentral accepts the rebuilt first message and its RDP
	// client reaches the device's port (a TPKT header; the account travels
	// later, inside CredSSP, which the test's stand-in does not speak, so the
	// gateway tests check the message itself).
	stepped := r.session(techID)
	r.exec(`UPDATE sessions SET stepped_up_at = now() WHERE id = $1`, stepped)
	_, head := rdp(stepped, 45*time.Second)
	if len(head) < 4 || head[0] != 3 || head[1] != 0 {
		t.Errorf("the device's RDP port got %x, want a connection request", head)
	}
	if r.count(`SELECT count(*) FROM audit_log WHERE action = 'rdp_credential.used'`) != 1 {
		t.Error("the use was not audited")
	}
	var details string
	if err := r.db.ReadTx(r.ctx, database.System, func(tx pgx.Tx) error {
		return tx.QueryRow(r.ctx, `SELECT coalesce(string_agg(details::text, ' '), '') FROM audit_log`).Scan(&details)
	}); err != nil {
		t.Fatal(err)
	}
	if strings.Contains(details, savedRDPPassword) {
		t.Error("the password is in the audit log")
	}

	// MeshCentral kept nothing: its database holds neither the password nor
	// the account (it would have, had savepass reached it).
	data, err := os.ReadFile(filepath.Join(filepath.Dir(r.env.Dir), "data", "meshcentral.db")) //nolint:gosec // test environment directory
	if err != nil {
		t.Fatal(err)
	}
	for _, s := range []string{savedRDPPassword, "svc-saved", "TESTDOM"} {
		if bytes.Contains(data, []byte(s)) {
			t.Errorf("MeshCentral's database holds %q", s)
		}
	}

	// MeshCentral's own port is not a way around the gateway: a browser
	// without a grant is refused there too, whatever it sends.
	//nolint:bodyclose // coder/websocket owns the handshake response body
	direct, _, derr := websocket.Dial(r.ctx, "ws"+strings.TrimPrefix(r.env.URL, "http")+"/mstscrelay.ashx", &websocket.DialOptions{HTTPHeader: http.Header{"Origin": {r.env.URL}}})
	if derr == nil {
		_ = direct.Write(r.ctx, websocket.MessageText, []byte(`["infos",{"ip":"`+dev.MeshNodeID+`","port":3389,"username":"x","password":"y","options":{"savepass":true}}]`))
		rctx, cancel := context.WithTimeout(r.ctx, 5*time.Second)
		_, _, rerr := direct.Read(rctx)
		cancel()
		_ = direct.CloseNow()
		if rerr == nil {
			t.Error("MeshCentral's RDP relay answered a browser that has no MeshCentral session")
		}
	}
	select {
	case head := <-arrived:
		t.Errorf("a request around the gateway reached the device: %q", head)
	case <-time.After(2 * time.Second):
	}
}
