//go:build windows

package authenticode

import (
	"bytes"
	"crypto"
	"os"
	"os/exec"
	"path/filepath"
	"slices"
	"strings"
	"testing"
)

// signtool finds the Windows SDK's signtool.exe, the newest version for
// x64. In CI (GITHUB_ACTIONS) a missing signtool fails the test rather than
// skipping it, so the interop check cannot silently stop running.
func signtool(t *testing.T) string {
	t.Helper()
	if p, err := exec.LookPath("signtool.exe"); err == nil {
		return p
	}
	found, _ := filepath.Glob(filepath.Join(os.Getenv("ProgramFiles(x86)"), `Windows Kits\10\bin\*\x64\signtool.exe`))
	if len(found) == 0 {
		if os.Getenv("GITHUB_ACTIONS") == "true" {
			t.Fatal("signtool.exe not found in the Windows SDK")
		}
		t.Skip("signtool.exe not found; install the Windows SDK")
	}
	slices.Sort(found) // 10.0.22621.0 before 10.0.26100.0: same width
	return found[len(found)-1]
}

// testCertificate makes a self-signed code signing certificate in the
// current user's store, exports it with its key to a PFX in dir, and
// removes it from the store when the test ends.
func testCertificate(t *testing.T, dir, name, keyAlgorithm string) string {
	t.Helper()
	pfx := filepath.Join(dir, name+".pfx")
	script := `$ErrorActionPreference = 'Stop'
$c = New-SelfSignedCertificate -Type CodeSigningCert -Subject 'CN=EasyRMM signtool test (` + name + `)' ` +
		`-KeyAlgorithm ` + keyAlgorithm + ` -KeyExportPolicy Exportable -CertStoreLocation Cert:\CurrentUser\My -NotAfter (Get-Date).AddDays(2)
$pw = ConvertTo-SecureString -String 'test' -Force -AsPlainText
Export-PfxCertificate -Cert $c -FilePath '` + pfx + `' -Password $pw | Out-Null
Write-Output $c.Thumbprint`
	out, err := exec.Command("powershell.exe", "-NoProfile", "-NonInteractive", "-Command", script).CombinedOutput()
	if err != nil {
		t.Fatalf("New-SelfSignedCertificate: %v\n%s", err, out)
	}
	thumb := strings.TrimSpace(string(out))
	t.Cleanup(func() {
		_ = exec.Command("powershell.exe", "-NoProfile", "-NonInteractive", "-Command",
			`Remove-Item -Path Cert:\CurrentUser\My\`+thumb).Run()
	})
	return pfx
}

func sign(t *testing.T, tool string, args ...string) {
	t.Helper()
	if out, err := exec.Command(tool, append([]string{"sign"}, args...)...).CombinedOutput(); err != nil {
		t.Fatalf("signtool sign %s: %v\n%s", strings.Join(args, " "), err, out)
	}
}

// signedCopy copies src into dir as name and returns its path.
func signedCopy(t *testing.T, src []byte, dir, name string) string {
	t.Helper()
	p := filepath.Join(dir, name)
	if err := os.WriteFile(p, src, 0o600); err != nil {
		t.Fatal(err)
	}
	return p
}

// TestSigntoolOnWindows signs programs with Microsoft's signtool, as an
// operator would, and checks that the reader accepts what it made: RSA and
// ECDSA keys, SHA-256 and SHA-384 digests, and a nested second signature
// (/as). EASYRMM_AUTHENTICODE_PROGRAM names one more program to sign, such
// as the Windows agent CI just built.
func TestSigntoolOnWindows(t *testing.T) {
	tool := signtool(t)
	dir := t.TempDir()
	rsa := testCertificate(t, dir, "rsa", "RSA")
	ecdsa := testCertificate(t, dir, "ecdsa", "ECDSA_nistP256")

	programs := map[string][]byte{"tiny.exe": read(t, "tiny.exe")}
	if extra := os.Getenv("EASYRMM_AUTHENTICODE_PROGRAM"); extra != "" {
		b, err := os.ReadFile(extra)
		if err != nil {
			t.Fatal(err)
		}
		programs[filepath.Base(extra)] = b
	}
	for name, unsigned := range programs {
		for _, c := range []struct {
			label, pfx, fd string
			hash           crypto.Hash
			nest           bool
		}{
			{"rsa-sha256", rsa, "SHA256", crypto.SHA256, false},
			{"ecdsa-sha256", ecdsa, "SHA256", crypto.SHA256, false},
			{"rsa-sha384", rsa, "SHA384", crypto.SHA384, false},
			{"rsa-sha256-nested", rsa, "SHA256", crypto.SHA256, true},
		} {
			t.Run(name+"/"+c.label, func(t *testing.T) {
				p := signedCopy(t, unsigned, dir, c.label+"-"+name)
				sign(t, tool, "/fd", c.fd, "/f", c.pfx, "/p", "test", p)
				if c.nest {
					sign(t, tool, "/as", "/fd", "SHA256", "/f", ecdsa, "/p", "test", p)
				}
				signed, err := os.ReadFile(p)
				if err != nil {
					t.Fatal(err)
				}
				if bytes.Equal(signed, unsigned) {
					t.Fatal("signtool left the file as it was")
				}
				sig, err := Verify(signed)
				if err != nil {
					t.Fatalf("Verify: %v", err)
				}
				if !strings.HasPrefix(sig.Signer.Subject.CommonName, "EasyRMM signtool test (") || sig.Hash != c.hash {
					t.Errorf("signer %q, hash %v", sig.Signer.Subject.CommonName, sig.Hash)
				}
				// The signature changes the file, not its Authenticode digest.
				want, err := Digest(unsigned, c.hash)
				if err != nil {
					t.Fatal(err)
				}
				if !bytes.Equal(sig.Digest, want) {
					t.Errorf("signed digest %x, unsigned program's %x", sig.Digest, want)
				}
				if c.nest != (sig.Nested == 1) {
					t.Errorf("%d nested signatures", sig.Nested)
				}
			})
		}
	}
}
