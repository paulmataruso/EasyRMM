package jobkeys

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"testing"
	"time"

	"github.com/google/uuid"

	"github.com/paulmataruso/easyrmm/internal/agentproto"
)

// Static is a Source with one key and no ring: it signs for every device with
// that key, records nothing and flags nothing, and says it takes no logs.
func TestStaticSource(t *testing.T) {
	if Static(nil) != nil {
		t.Fatal("a source from no key")
	}
	_, priv, _ := ed25519.GenerateKey(rand.Reader)
	s := Static(priv)
	ctx := context.Background()
	dev := uuid.New()
	c, err := s.For(ctx, nil, dev)
	if err != nil || !c.Key.Held() || c.NeedsRepinning || c.Key.Generation != 1 || !c.Key.Public.Equal(priv.Public()) {
		t.Fatalf("For: %+v %v", c, err)
	}
	key, k, err := s.Issue(ctx, nil, dev, agentproto.InstructionJob, "run")
	if err != nil || !key.Equal(priv) || k.Fingerprint() != agentproto.Fingerprint(priv.Public().(ed25519.PublicKey)) {
		t.Fatalf("Issue: %v", err)
	}
	if !s.Newest().Public.Equal(priv.Public()) || s.Logs() {
		t.Error("Newest or Logs")
	}
	if err := s.Observe(ctx, nil, Observation{}); err != nil {
		t.Error(err)
	}
	if err := s.RefusedStatement(ctx, nil, Observation{}, agentproto.KeyRefusal{}); err != nil {
		t.Error(err)
	}
	res, err := s.AcceptLog(ctx, nil, LogDevice{}, agentproto.InstructionLogReport{Acked: 7}, time.Now())
	if err != nil || res.Ack != 7 {
		t.Errorf("AcceptLog: %+v %v", res, err)
	}
}

func TestKeyNamesAndGenerationOrder(t *testing.T) {
	_, priv, _ := ed25519.GenerateKey(rand.Reader)
	k := Key{Generation: 3, Public: priv.Public().(ed25519.PublicKey)}
	if k.Held() || k.Encoded() != agentproto.EncodeKey(k.Public) || len(k.Fingerprint()) != 32 {
		t.Error("key names")
	}
	if aad(3) == nil || string(aad(3)) != "easyrmm:job_key:3" {
		t.Errorf("additional data %q", aad(3))
	}
}
