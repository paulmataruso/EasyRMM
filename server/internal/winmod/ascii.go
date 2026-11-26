package winmod

import (
	"encoding/json"
	"strconv"
	"unicode/utf16"
	"unicode/utf8"
)

// MarshalParams encodes a job's parameters as JSON that is plain ASCII: every
// character above U+007F is written as a \uXXXX escape (a surrogate pair above
// U+FFFF). The agent writes the document to a script's standard input as
// bytes, and Windows PowerShell 5.1 reads standard input in the console's
// code page (OEM, not UTF-8), so a raw UTF-8 name would arrive altered. The
// escaped document decodes to exactly the same values in any code page.
func MarshalParams(v any) ([]byte, error) {
	b, err := json.Marshal(v)
	if err != nil {
		return nil, err
	}
	return asciiOnly(b), nil
}

// asciiOnly escapes the non-ASCII characters of valid JSON text. Such a
// character can only be inside a string, where the escape is equivalent.
func asciiOnly(b []byte) []byte {
	out := make([]byte, 0, len(b))
	for i := 0; i < len(b); {
		if b[i] < utf8.RuneSelf {
			out = append(out, b[i])
			i++
			continue
		}
		r, n := utf8.DecodeRune(b[i:])
		i += n
		if r1, r2 := utf16.EncodeRune(r); r1 != utf8.RuneError || r2 != utf8.RuneError {
			if r >= 0x10000 {
				out = appendU(out, r1)
				out = appendU(out, r2)
				continue
			}
		}
		out = appendU(out, r)
	}
	return out
}

func appendU(out []byte, r rune) []byte {
	h := strconv.FormatInt(int64(r), 16)
	out = append(out, '\\', 'u')
	for k := len(h); k < 4; k++ {
		out = append(out, '0')
	}
	return append(out, h...)
}
