package release

import (
	"slices"
	"testing"
)

func TestParseVersionForms(t *testing.T) {
	for _, tc := range []struct {
		in             string
		kind           Kind
		tag, imageTag  string
		rc, run, tries uint64
	}{
		{"v1.2.3", KindRelease, "easyrmm-v1.2.3", "1.2.3", 0, 0, 0},
		{"v0.0.0", KindRelease, "easyrmm-v0.0.0", "0.0.0", 0, 0, 0},
		{"v1.0.0-rc.4", KindCandidate, "easyrmm-v1.0.0-rc.4", "1.0.0-rc.4", 4, 0, 0},
		{"v1.0.0-rc.4.edge.412.1", KindEdge, "", "1.0.0-rc.4.edge.412.1", 4, 412, 1},
		{"v1.0.1-edge.415.2", KindEdge, "", "1.0.1-edge.415.2", 0, 415, 2},
		{"v123456789.0.0", KindRelease, "easyrmm-v123456789.0.0", "123456789.0.0", 0, 0, 0},
	} {
		v, err := ParseVersion(tc.in)
		if err != nil {
			t.Fatalf("ParseVersion(%q): %v", tc.in, err)
		}
		if v.String() != tc.in || v.Kind() != tc.kind || v.Tag() != tc.tag || v.ImageTag() != tc.imageTag ||
			v.rc != tc.rc || v.run != tc.run || v.attempt != tc.tries || v.IsZero() {
			t.Errorf("ParseVersion(%q) = %+v (kind %v, tag %q, image tag %q)", tc.in, v, v.Kind(), v.Tag(), v.ImageTag())
		}
	}
}

func TestParseVersionRefusesEverythingElse(t *testing.T) {
	for _, in := range []string{
		"", "1.2.3", "v1.2", "v1.2.3.4", "V1.2.3", "v01.2.3", "v1.02.3", "v1.2.03",
		"v1.2.3-rc.0", "v1.2.3-rc.01", "v1.2.3-rc", "v1.2.3-beta.1", "v1.2.3-RC.1",
		"v1.2.3-rc.1.edge.0.1", "v1.2.3-rc.1.edge.1.0", "v1.2.3-rc.1.edge.1", "v1.2.3-edge.1",
		"v1.2.3-edge.0.1", "v1.2.3-edge.1.1.1", "v1.2.3-edge.412.1-rc.1", "v1.2.3+build",
		"v1.2.3-rc.5-edge.412", "v1234567890.0.0", "edge-1df9b49", "dev", "latest",
		"v1.2.3\n", " v1.2.3", "v1.2.3-rc.1/../../x",
	} {
		if v, err := ParseVersion(in); err == nil {
			t.Errorf("ParseVersion(%q) = %v, want an error", in, v)
		}
	}
}

func TestMustParseVersionPanics(t *testing.T) {
	defer func() {
		if recover() == nil {
			t.Error("MustParseVersion of a bad version did not panic")
		}
	}()
	MustParseVersion("1.2.3")
}

func TestVersionsSort(t *testing.T) {
	// Ascending, ADR-0052's examples among them.
	ordered := []string{
		"v0.9.9",
		"v1.0.0-rc.1",
		"v1.0.0-rc.4",
		"v1.0.0-rc.4.edge.9.1",
		"v1.0.0-rc.4.edge.412.1",
		"v1.0.0-rc.4.edge.412.2",
		"v1.0.0-rc.4.edge.413.1",
		"v1.0.0-rc.5",
		"v1.0.0-rc.10",
		"v1.0.0",
		"v1.0.1-edge.415.1",
		"v1.0.1-edge.1000.1",
		"v1.0.1-rc.1",
		"v1.0.1-rc.1.edge.416.1",
		"v1.0.1",
		"v1.1.0",
		"v2.0.0",
		"v10.0.0",
	}
	for i := range ordered {
		for j := range ordered {
			a, b := MustParseVersion(ordered[i]), MustParseVersion(ordered[j])
			want := 0
			switch {
			case i < j:
				want = -1
			case i > j:
				want = 1
			}
			if got := a.Compare(b); got != want {
				t.Errorf("%s.Compare(%s) = %d, want %d", a, b, got, want)
			}
		}
	}
	shuffled := []Version{}
	for _, i := range []int{7, 2, 16, 0, 11, 4, 9, 13, 1, 17, 5, 14, 3, 10, 15, 6, 12, 8} {
		shuffled = append(shuffled, MustParseVersion(ordered[i]))
	}
	slices.SortFunc(shuffled, Version.Compare)
	for i, v := range shuffled {
		if v.String() != ordered[i] {
			t.Fatalf("sorted[%d] = %s, want %s", i, v, ordered[i])
		}
	}
}

func TestChannels(t *testing.T) {
	for _, tc := range []struct {
		ch                    Channel
		release, rc, edge     bool
		newest                string
		newestWithoutReleases string
	}{
		{ChannelStable, true, false, false, "v1.0.0", ""},
		{ChannelPreRelease, true, true, false, "v1.0.1-rc.1", "v1.0.1-rc.1"},
		{ChannelEdge, true, true, true, "v1.0.1-rc.1.edge.7.1", "v1.0.1-rc.1"},
	} {
		if tc.ch.Admits(KindRelease) != tc.release || tc.ch.Admits(KindCandidate) != tc.rc || tc.ch.Admits(KindEdge) != tc.edge {
			t.Errorf("%s admits release %v, candidate %v, edge %v", tc.ch, tc.ch.Admits(KindRelease), tc.ch.Admits(KindCandidate), tc.ch.Admits(KindEdge))
		}
		all := []Version{
			MustParseVersion("v0.9.0"), MustParseVersion("v1.0.1-rc.1"), MustParseVersion("v1.0.0"),
			MustParseVersion("v1.0.1-rc.1.edge.7.1"), MustParseVersion("v1.0.1-edge.3.1"),
		}
		if got, ok := tc.ch.Newest(all); !ok || got.String() != tc.newest {
			t.Errorf("%s.Newest = %v, %v; want %s", tc.ch, got, ok, tc.newest)
		}
		got, ok := tc.ch.Newest(all[1:2])
		if ok != (tc.newestWithoutReleases != "") || (ok && got.String() != tc.newestWithoutReleases) {
			t.Errorf("%s.Newest(rc only) = %v, %v; want %q", tc.ch, got, ok, tc.newestWithoutReleases)
		}
		if parsed, err := ParseChannel(string(tc.ch)); err != nil || parsed != tc.ch {
			t.Errorf("ParseChannel(%q) = %q, %v", tc.ch, parsed, err)
		}
	}
	if _, ok := ChannelEdge.Newest(nil); ok {
		t.Error("Newest of nothing reported a version")
	}
	for _, s := range []string{"", "Stable", "prerelease", "beta", "main"} {
		if _, err := ParseChannel(s); err == nil {
			t.Errorf("ParseChannel(%q) accepted it", s)
		}
	}
	if Channel("other").Admits(KindRelease) {
		t.Error("an unknown channel admits releases")
	}
}

func TestKindNames(t *testing.T) {
	for k, want := range map[Kind]string{KindRelease: "release", KindCandidate: "release candidate", KindEdge: "edge build", 0: "unknown"} {
		if k.String() != want {
			t.Errorf("Kind(%d) = %q, want %q", k, k, want)
		}
	}
}
