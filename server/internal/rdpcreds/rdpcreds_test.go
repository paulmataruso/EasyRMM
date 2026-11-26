package rdpcreds

import (
	"bytes"
	"strings"
	"testing"

	"github.com/google/uuid"
)

func TestAssociatedDataBindsRowDeviceScopeAndPerson(t *testing.T) {
	id, dev, user, other := uuid.New(), uuid.New(), uuid.New(), uuid.New()
	base := associatedData(id, dev, ScopeUser, &user)
	for name, ad := range map[string][]byte{
		"row":    associatedData(uuid.New(), dev, ScopeUser, &user),
		"device": associatedData(id, uuid.New(), ScopeUser, &user),
		"scope":  associatedData(id, dev, ScopeDevice, &user),
		"person": associatedData(id, dev, ScopeUser, &other),
		"null":   associatedData(id, dev, ScopeUser, nil),
	} {
		if bytes.Equal(base, ad) {
			t.Errorf("a different %s has the same associated data", name)
		}
	}
	shared := string(associatedData(id, dev, ScopeDevice, nil))
	if want := "rdp-credential:" + id.String() + ":" + dev.String() + ":device:-"; shared != want {
		t.Errorf("shared: %s", shared)
	}
	if !strings.HasSuffix(string(base), ":user:"+user.String()) {
		t.Errorf("personal: %s", base)
	}
}

func TestSaveInputValidation(t *testing.T) {
	ok := SaveInput{Username: "u", Password: []byte("p")}
	if err := ok.validate(); err != nil {
		t.Fatal(err)
	}
	for name, in := range map[string]SaveInput{
		"no user":       {Password: []byte("p")},
		"no password":   {Username: "u"},
		"nul":           {Username: "u", Password: []byte{'a', 0}},
		"invalid UTF-8": {Username: "u", Password: []byte{0xff}},
		"long":          {Username: "u", Password: bytes.Repeat([]byte("p"), maxPassword+1)},
		"label":         {Username: "u", Password: []byte("p"), Label: strings.Repeat("x", maxLabel+1)},
		"domain":        {Username: "u", Password: []byte("p"), Domain: strings.Repeat("x", maxDomain+1)},
	} {
		if err := in.validate(); err == nil {
			t.Errorf("%s accepted", name)
		}
	}
}
