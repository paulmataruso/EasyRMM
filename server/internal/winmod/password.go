package winmod

import (
	"crypto/rand"
	"math/big"
)

// A generated password has 20 characters from four classes, none of them
// easy to mistake for another (no 0 O o 1 l I |), so it can be read aloud or
// typed from a screen (ADR-0075 section 2).
const (
	passwordLength = 20
	pwUpper        = "ABCDEFGHJKLMNPQRSTUVWXYZ"
	pwLower        = "abcdefghijkmnpqrstuvwxyz"
	pwDigit        = "23456789"
	pwSymbol       = "!#$%&*+-=?@^_" //nolint:gosec // the characters a password is made from, not a credential
)

// GeneratePassword makes a password from a cryptographic source: at least
// one character of each class, the rest from all of them, shuffled.
func GeneratePassword() (string, error) {
	all := pwUpper + pwLower + pwDigit + pwSymbol
	chars := make([]byte, 0, passwordLength)
	for _, class := range []string{pwUpper, pwLower, pwDigit, pwSymbol} {
		c, err := pick(class)
		if err != nil {
			return "", err
		}
		chars = append(chars, c)
	}
	for len(chars) < passwordLength {
		c, err := pick(all)
		if err != nil {
			return "", err
		}
		chars = append(chars, c)
	}
	for i := len(chars) - 1; i > 0; i-- {
		j, err := rand.Int(rand.Reader, big.NewInt(int64(i+1)))
		if err != nil {
			return "", err
		}
		chars[i], chars[j.Int64()] = chars[j.Int64()], chars[i]
	}
	return string(chars), nil
}

func pick(set string) (byte, error) {
	n, err := rand.Int(rand.Reader, big.NewInt(int64(len(set))))
	if err != nil {
		return 0, err
	}
	return set[n.Int64()], nil
}
