package idp

import (
	"slices"
	"testing"
)

func TestTokenAMR(t *testing.T) {
	for _, tc := range []struct{ in, want []string }{
		{[]string{"pwd", "otp"}, []string{"pwd", "otp", "mfa"}},
		{[]string{"pwd", "rc"}, []string{"pwd", "rc", "mfa"}},
		{[]string{"hwk", "mfa"}, []string{"hwk", "mfa"}},
		{[]string{"fed", "mfa"}, []string{"fed", "mfa"}},
	} {
		in := slices.Clone(tc.in)
		if got := tokenAMR(in); !slices.Equal(got, tc.want) {
			t.Errorf("tokenAMR(%v) = %v, want %v", tc.in, got, tc.want)
		}
		if !slices.Equal(in, tc.in) {
			t.Errorf("tokenAMR changed its argument to %v", in)
		}
	}
}
