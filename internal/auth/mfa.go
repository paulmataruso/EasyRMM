package auth

import (
	"github.com/pquerna/otp"
	"github.com/pquerna/otp/totp"
)

const mfaIssuer = "EasyRMM"

func GenerateMFASecret(username string) (secret string, otpauthURL string, err error) {
	key, err := totp.Generate(totp.GenerateOpts{
		Issuer:      mfaIssuer,
		AccountName: username,
		Algorithm:   otp.AlgorithmSHA1,
		Digits:      otp.DigitsSix,
	})
	if err != nil {
		return "", "", err
	}
	return key.Secret(), key.URL(), nil
}

func ValidateMFACode(secret, code string) bool {
	return totp.Validate(code, secret)
}
