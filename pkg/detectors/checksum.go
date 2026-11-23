package detectors

import "hash/crc32"

const base62Alphabet = "0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz"

// CRC32Base62 renders crc32-IEEE(s) in base62 (0-9A-Za-z), left-padded with
// '0' to six characters: the checksum suffix of GitHub's prefixed tokens
// (ghp_, gho_, ghu_, ghs_, ghr_) and npm's npm_ tokens.
func CRC32Base62(s string) string {
	v := crc32.ChecksumIEEE([]byte(s))
	var b [6]byte
	for i := range b {
		b[i] = '0'
	}
	for i := 5; i >= 0 && v > 0; i-- {
		b[i] = base62Alphabet[v%62]
		v /= 62
	}
	return string(b[:])
}

// TokenChecksum classifies a 30+6 checksum-suffixed token body (the part
// after the "ghp_"/"npm_" prefix): "valid" when its last six characters
// are CRC32Base62 of the first thirty, "invalid" otherwise, and "" for a
// body of another length. An invalid checksum means the provider never
// issued the token (an example, a placeholder, or a truncated copy).
func TokenChecksum(body string) string {
	if len(body) != 36 {
		return ""
	}
	if CRC32Base62(body[:30]) == body[30:] {
		return "valid"
	}
	return "invalid"
}
