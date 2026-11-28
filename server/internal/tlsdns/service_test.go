package tlsdns

import (
	"fmt"
	"net/netip"
	"strings"
	"testing"
)

func TestIsCloudMetadata(t *testing.T) {
	tests := []struct {
		addr string
		want bool
	}{
		{"169.254.169.254", true},
		{"fd00:ec2::254", true},
		{"127.0.0.1", false},
		{"10.0.0.1", false},
		{"192.168.1.1", false},
		{"1.1.1.1", false},
		{"::1", false},
	}
	for _, tc := range tests {
		t.Run(tc.addr, func(t *testing.T) {
			got := isCloudMetadata(netip.MustParseAddr(tc.addr))
			if got != tc.want {
				t.Errorf("isCloudMetadata(%s) = %v, want %v", tc.addr, got, tc.want)
			}
		})
	}
}

func TestNormalizeZone(t *testing.T) {
	tests := []struct {
		in, want string
	}{
		{"example.com", "example.com"},
		{"Example.COM.", "example.com"},
		{" example.com ", "example.com"},
		{"EXAMPLE.COM.", "example.com"},
	}
	for _, tc := range tests {
		t.Run(tc.in, func(t *testing.T) {
			got := normalizeZone(tc.in)
			if got != tc.want {
				t.Errorf("normalizeZone(%q) = %q, want %q", tc.in, got, tc.want)
			}
		})
	}
}

func TestIsValidZone(t *testing.T) {
	tests := []struct {
		zone string
		want bool
	}{
		{"example.com", true},
		{"sub.example.com", true},
		{"a.b.c.d", true},
		{"", false},
		{"com", false},
		{".", false},
		{".example.com", false},
	}
	for _, tc := range tests {
		t.Run(tc.zone, func(t *testing.T) {
			got := isValidZone(tc.zone)
			if got != tc.want {
				t.Errorf("isValidZone(%q) = %v, want %v", tc.zone, got, tc.want)
			}
		})
	}
}

func TestAllowedTSIGAlgorithms(t *testing.T) {
	tests := []struct {
		alg  string
		want bool
	}{
		{"hmac-sha256", true},
		{"hmac-sha384", true},
		{"hmac-sha512", true},
		{"hmac-md5", false},
		{"hmac-sha1", false},
		{"HMAC-SHA256", true},
	}
	for _, tc := range tests {
		t.Run(tc.alg, func(t *testing.T) {
			alg := strings.ToLower(strings.TrimSuffix(tc.alg, ".")) + "."
			got := allowedTSIGAlgorithms[alg]
			if got != tc.want {
				t.Errorf("allowedTSIGAlgorithms[%q] = %v, want %v", alg, got, tc.want)
			}
		})
	}
}

func TestClassifyError(t *testing.T) {
	tests := []struct {
		msg  string
		want TestReason
	}{
		{"dns response error code \"Refused\"", ReasonRefused},
		{"i/o timeout", ReasonTimedOut},
		{"context deadline exceeded", ReasonTimedOut},
		{"TSIG verification failed", ReasonNotAuthorized},
		{"dns: NXDOMAIN", ReasonZoneNotFound},
		{"something else entirely", ReasonUnknown},
	}
	for _, tc := range tests {
		t.Run(tc.msg, func(t *testing.T) {
			got := classifyError(fmt.Errorf("%s", tc.msg))
			if got != tc.want {
				t.Errorf("classifyError(%q) = %q, want %q", tc.msg, got, tc.want)
			}
		})
	}
}
