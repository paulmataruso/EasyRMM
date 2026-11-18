// Command ssotestenv prepares the configuration for a disposable Dex, the
// OpenID Connect provider integration tests sign in through
// (scripts/test-oidc.sh). It writes dex.yaml and env.json with a client
// secret and a password generated for this run.
//
// Test use only: env.json holds them in the clear.
package main

import (
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"flag"
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"golang.org/x/crypto/bcrypt"

	"github.com/paulmataruso/easyrmm/server/internal/sso/ssotest"
)

func main() {
	dir := flag.String("dir", "", "directory to write into")
	listen := flag.String("listen", "127.0.0.1:25556", "Dex listen address")
	flag.Parse()
	if *dir == "" {
		fail(fmt.Errorf("-dir is required"))
	}
	if err := os.MkdirAll(*dir, 0o755); err != nil { //nolint:gosec // the Dex container reads it as another user
		fail(err)
	}
	env := ssotest.Settings{
		Issuer:       "http://" + *listen + "/dex",
		ClientID:     "easyrmm-test",
		ClientSecret: random(),
		PublicURL:    ssotest.PublicURL,
		Password:     random(),
	}
	hash, err := bcrypt.GenerateFromPassword([]byte(env.Password), bcrypt.DefaultCost) // Dex refuses less
	if err != nil {
		fail(err)
	}
	var b strings.Builder
	fmt.Fprintf(&b, "issuer: %s\nstorage:\n  type: memory\nweb:\n  http: %s\n", env.Issuer, *listen)
	b.WriteString("oauth2:\n  skipApprovalScreen: true\n  responseTypes: [code]\nenablePasswordDB: true\n")
	b.WriteString("logger:\n  level: info\n")
	fmt.Fprintf(&b, "staticClients:\n- id: %s\n  name: EasyRMM tests\n  secret: %s\n  redirectURIs:\n  - %s\n  - %s\n",
		env.ClientID, env.ClientSecret, env.PublicURL+"/api/v1/auth/sso/callback", ssotest.AppPublicURL+"/api/v1/auth/sso/callback")
	b.WriteString("staticPasswords:\n")
	for i, u := range ssotest.Users {
		fmt.Fprintf(&b, "- email: %q\n  username: %q\n  userID: \"00000000-0000-4000-8000-%012d\"\n  hash: %q\n",
			u, strings.Split(u, "@")[0], i+1, hash)
	}
	if err := os.WriteFile(filepath.Join(*dir, "dex.yaml"), []byte(b.String()), 0o644); err != nil { //nolint:gosec // read by the Dex container's user
		fail(err)
	}
	raw, err := json.MarshalIndent(env, "", "  ") //nolint:gosec // G117: test-only settings, generated for this run, for the tests to read
	if err != nil {
		fail(err)
	}
	if err := os.WriteFile(filepath.Join(*dir, "env.json"), raw, 0o600); err != nil {
		fail(err)
	}
}

func random() string {
	b := make([]byte, 24)
	if _, err := rand.Read(b); err != nil {
		fail(err)
	}
	return hex.EncodeToString(b)
}

func fail(err error) {
	fmt.Fprintln(os.Stderr, "ssotestenv:", err)
	os.Exit(1)
}
