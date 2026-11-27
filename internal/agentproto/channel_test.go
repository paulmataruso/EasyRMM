package agentproto

import (
	"bytes"
	"crypto/ed25519"
	"errors"
	"strings"
	"testing"
	"time"
)

func testKey(b byte) ed25519.PrivateKey {
	return ed25519.NewKeyFromSeed(bytes.Repeat([]byte{b}, ed25519.SeedSize))
}

var testSent = time.Date(2026, 11, 26, 12, 0, 0, 0, time.UTC)

// Golden vectors: a change to either frame breaks both sides, so it must be
// deliberate.
const (
	goldenServerFrame = `{"payload":"eyJ2IjoxLCJ0eXBlIjoiaGVsbG8iLCJkZXZpY2VJZCI6ImRldi0xIiwiY29ubklkIjoiYzEiLCJzZXEiOjEsInNlbnRBdCI6IjIwMjYtMTEtMjZUMTI6MDA6MDBaIiwibm9uY2UiOiJuMSIsImZlYXR1cmVzIjpbImNoYW5uZWwiXSwiaW5zdGFuY2UiOiJpMSJ9","signature":"bkNdH33se6yg53ct34OAwpPMGJDXIuZxaW6lBwlS/Lp4SWbHY3sgPCzj8QCGN9Yi7Xxr1uPP3QqU4zRvh1PUDg=="}`
	goldenAgentFrame  = `{"payload":"eyJ2IjoxLCJ0eXBlIjoibG9ncy5iYXRjaCIsImNvbm5JZCI6ImMxIiwic2VxIjoxLCJiYXRjaCI6eyJyZWNvcmRzIjpbeyJzZXEiOjEsInRpbWUiOiIyMDI2LTExLTI2VDEyOjAwOjAwWiIsInNvdXJjZSI6ImFnZW50IiwibGV2ZWwiOiJpbmZvIiwibWVzc2FnZSI6Im0ifV19fQ==","signature":"u88yhxokfT20k9Xli/9SaSljHssMifTpa6IPH3L7IBkZynI5wzfhttpNx5DDb8Hq33t7P/c/0eevOwTMUnsXDQ=="}`
)

func helloMsg() ChannelMessage {
	return ChannelMessage{V: 1, Type: TypeHello, DeviceID: "dev-1", ConnID: "c1", Seq: 1, SentAt: testSent,
		Nonce: "n1", Features: []string{FeatureChannel}, Instance: "i1"}
}

func TestChannelServerGolden(t *testing.T) {
	frame, err := SignChannelMessage(testKey(1), helloMsg())
	if err != nil {
		t.Fatal(err)
	}
	if string(frame) != goldenServerFrame {
		t.Fatalf("server frame changed:\n%s", frame)
	}
}

func TestChannelAgentGolden(t *testing.T) {
	frame, err := SignChannelAgentFrame(testKey(2), ChannelAgentFrame{Type: TypeLogsBatch, ConnID: "c1", Seq: 1,
		Batch: &LogBatch{Records: []LogRecord{{Seq: 1, Time: testSent, Source: "agent", Level: "info", Message: "m"}}}})
	if err != nil {
		t.Fatal(err)
	}
	if string(frame) != goldenAgentFrame {
		t.Fatalf("agent frame changed:\n%s", frame)
	}
}

func TestChannelServerRoundTripAndRefusals(t *testing.T) {
	priv := testKey(1)
	pub := priv.Public().(ed25519.PublicKey)
	frame, _ := SignChannelMessage(priv, helloMsg())
	m, err := VerifyChannelMessage(pub, frame, MaxChannelFrame)
	if err != nil || m.Type != TypeHello || m.Nonce != "n1" || !m.SentAt.Equal(testSent) {
		t.Fatalf("verify: %+v %v", m, err)
	}
	if err := m.Check("dev-1", "c1", 1); err != nil {
		t.Errorf("check: %v", err)
	}
	for name, c := range map[string][3]any{
		"device": {"dev-2", "c1", uint64(1)}, "conn": {"dev-1", "c2", uint64(1)},
		"gap": {"dev-1", "c1", uint64(2)}, "repeat": {"dev-1", "c1", uint64(0)},
	} {
		if err := m.Check(c[0].(string), c[1].(string), c[2].(uint64)); !errors.Is(err, ErrChannelBinding) {
			t.Errorf("%s: %v", name, err)
		}
	}
	other := testKey(9).Public().(ed25519.PublicKey)
	if _, err := VerifyChannelMessage(other, frame, MaxChannelFrame); !errors.Is(err, ErrChannelSignature) {
		t.Errorf("another key: %v", err)
	}
	if _, err := VerifyChannelMessage(pub, frame, 10); !errors.Is(err, ErrChannelFrame) {
		t.Errorf("oversized: %v", err)
	}
	// A frame signed in the agent's domain is not the server's.
	a, _ := SignChannelAgentFrame(priv, ChannelAgentFrame{Type: TypeLogsBatch, ConnID: "c1", Seq: 1})
	if _, err := VerifyChannelMessage(pub, a, MaxChannelAgentFrame); err == nil {
		t.Error("an agent frame verified as a server's")
	}
	tampered := strings.Replace(string(frame), `"signature":"`, `"signature":"A`, 1)
	if _, err := VerifyChannelMessage(pub, []byte(tampered), MaxChannelFrame); err == nil {
		t.Error("tampered signature verified")
	}
	for _, bad := range []string{`not json`, `{"payload":"!!","signature":""}`, `{"payload":"","signature":"!!"}`} {
		if _, err := VerifyChannelMessage(pub, []byte(bad), MaxChannelFrame); !errors.Is(err, ErrChannelFrame) {
			t.Errorf("%q: %v", bad, err)
		}
	}
	if _, err := VerifyChannelMessage(Keys(nil), frame, MaxChannelFrame); err == nil {
		t.Error("no key verified")
	}
}

func TestChannelAgentRoundTripAndRefusals(t *testing.T) {
	priv := testKey(2)
	pub := priv.Public().(ed25519.PublicKey)
	frame, err := SignChannelAgentFrame(priv, ChannelAgentFrame{Type: TypeLogsBatch, ConnID: "c1", Seq: 7, Batch: &LogBatch{}})
	if err != nil {
		t.Fatal(err)
	}
	f, err := VerifyChannelAgentFrame(pub, frame)
	if err != nil || f.Seq != 7 || f.ConnID != "c1" || f.Type != TypeLogsBatch || f.V != 1 {
		t.Fatalf("verify: %+v %v", f, err)
	}
	if _, err := VerifyChannelAgentFrame(testKey(3).Public().(ed25519.PublicKey), frame); !errors.Is(err, ErrChannelSignature) {
		t.Errorf("another key: %v", err)
	}
	if _, err := VerifyChannelAgentFrame(pub, append(frame, bytes.Repeat([]byte(" "), MaxChannelAgentFrame)...)); !errors.Is(err, ErrChannelFrame) {
		t.Errorf("oversized: %v", err)
	}
	if _, err := VerifyChannelAgentFrame(pub, []byte(`{`)); !errors.Is(err, ErrChannelFrame) {
		t.Errorf("malformed: %v", err)
	}
	// The signature covers the connection and position, not only the payload:
	// a payload re-wrapped under another seq in the signed message fails.
	if agentMessageDiffers := bytes.Equal(agentMessage("c1", 1, []byte("p")), agentMessage("c1", 2, []byte("p"))); agentMessageDiffers {
		t.Error("seq not bound")
	}
	if bytes.Equal(agentMessage("c1", 1, []byte("p")), agentMessage("c2", 1, []byte("p"))) {
		t.Error("connection not bound")
	}
}
