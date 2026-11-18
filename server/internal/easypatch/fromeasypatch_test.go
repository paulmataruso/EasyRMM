package easypatch

import (
	"testing"

	"github.com/google/uuid"
)

func TestLandingFor(t *testing.T) {
	d, o, j := uuid.New(), uuid.New(), uuid.New()
	for _, c := range []struct {
		kind         string
		dev, org, jb uuid.UUID
		want         Landing
	}{
		{"endpoints", d, uuid.Nil, uuid.Nil, Landing{Path: "/devices/" + d.String() + "?tab=patches"}},
		{"endpoints", uuid.Nil, uuid.Nil, uuid.Nil, Landing{Path: "/patching", Notice: noticeEndpoint}},
		{"organizations", uuid.Nil, o, uuid.Nil, Landing{Path: "/organizations/" + o.String()}},
		{"organizations", uuid.Nil, uuid.Nil, uuid.Nil, Landing{Path: "/patching", Notice: noticeOrganization}},
		{"jobs", uuid.Nil, uuid.Nil, j, Landing{Path: "/patching?tab=jobs&job=" + j.String()}},
		{"other", d, o, j, Landing{Path: "/patching"}},
	} {
		if got := landingFor(c.kind, c.dev, c.org, c.jb); got != c.want {
			t.Errorf("%s: %+v, want %+v", c.kind, got, c.want)
		}
	}
}
