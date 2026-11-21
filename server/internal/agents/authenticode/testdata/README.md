# Authenticode test programs

The reader in `authenticode.go` is tested against these files
(`authenticode_test.go`). They are real Windows programs, signed with
throwaway certificates whose private keys were deleted after signing: the
signatures prove nothing about anyone.

| File | What it is |
|---|---|
| `tiny.c` | The source of `tiny.exe`: a `main` that returns 0 |
| `tiny.exe` | `tiny.c` built for x86-64 with MinGW-w64's GCC 13 (`x86_64-w64-mingw32-gcc`), stripped; unsigned |
| `tiny-rsa.exe` | `tiny.exe` signed with an RSA 2048 key, SHA-256, certificate for code signing (CN "EasyRMM test signer (rsa)") |
| `tiny-ecdsa.exe` | The same with an ECDSA P-256 key (CN "EasyRMM test signer (ecdsa)") |
| `tiny-noeku.exe` | Signed with a certificate whose extended key usage is server authentication only, which the reader refuses |
| `tiny-nested.exe` | `tiny-rsa.exe` with a second signature nested in the first (`osslsigncode -nest`, like `signtool /as`) |
| `tiny-rfc3161.exe` | `tiny.exe` signed with an RSA 2048 key and an RFC 3161 timestamp from DigiCert's timestamp server (`osslsigncode -ts`, like `signtool /tr`); CN "EasyRMM test signer (timestamped)" |
| `tiny-legacy-ts.exe` | The same with an Authenticode countersignature timestamp (`osslsigncode -t`, like `signtool /t`) |

Signed with osslsigncode 2.9:

```bash
osslsigncode sign -certs rsa.crt -key rsa.key -h sha256 -n "EasyRMM test" \
  -in tiny.exe -out tiny-rsa.exe
osslsigncode sign -certs ecdsa.crt -key ecdsa.key -h sha256 -nest \
  -in tiny-rsa.exe -out tiny-nested.exe
osslsigncode sign -certs ts.crt -key ts.key -h sha256 -n "EasyRMM test" \
  -ts http://timestamp.digicert.com -in tiny.exe -out tiny-rfc3161.exe
osslsigncode sign -certs ts.crt -key ts.key -h sha256 -n "EasyRMM test" \
  -t http://timestamp.digicert.com -in tiny.exe -out tiny-legacy-ts.exe
```

The certificates are self-signed, made with `openssl req -x509` and
`-addext extendedKeyUsage=codeSigning` (`serverAuth` for the
`noeku` one). To make the files again, make new keys and certificates the
same way. Rebuilding `tiny.exe` changes its digest: update `tinyDigest` in
the test from `osslsigncode verify` ("Calculated message digest").

On Windows, `TestSigntoolOnWindows` also signs `tiny.exe` with `signtool`
and a certificate it makes for the test, and reads the result.
