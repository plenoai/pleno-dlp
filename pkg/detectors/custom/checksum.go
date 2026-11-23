package custom

import (
	"errors"
	"fmt"
	"hash/crc32"
	"regexp"
	"strings"
)

// Checksum configures offline structural validation of a match. Candidates
// that fail the checksum are dropped before any result is emitted, so a
// checksum-bearing token format (GitHub-style CRC32 suffixes, Luhn card
// numbers, IBANs) produces near-zero false positives without network I/O.
//
//	"checksum": {
//	  "algorithm":      "crc32_base62",
//	  "body_group":     "body",
//	  "checksum_group": "crc",
//	  "length":         6
//	}
//
// Algorithms:
//   - luhn, iban: the body (body_group, or the whole match) must satisfy the
//     check digit; checksum_group and length are not used.
//   - crc32_base62, crc32_hex, crc32_dec: CRC32-IEEE of the body, rendered
//     as base62 / lowercase hex / decimal, left-padded with '0' to length and
//     truncated to its last length characters, must equal checksum_group.
type Checksum struct {
	Algorithm     string `json:"algorithm"`
	BodyGroup     string `json:"body_group,omitempty"`
	ChecksumGroup string `json:"checksum_group,omitempty"`
	Length        int    `json:"length,omitempty"`
}

type checksumCheck struct {
	cfg       Checksum
	bodyIdx   int // -1 = whole match
	sumIdx    int
	algorithm func(body, sum string) bool
}

func compileChecksum(c *Checksum, re *regexp.Regexp) (*checksumCheck, error) {
	if c == nil {
		return nil, nil
	}
	cc := &checksumCheck{cfg: *c, bodyIdx: -1, sumIdx: -1}
	group := func(name, field string) (int, error) {
		idx := re.SubexpIndex(name)
		if idx < 0 {
			return 0, fmt.Errorf("checksum.%s %q is not a named capture group in regex", field, name)
		}
		return idx, nil
	}
	var err error
	if c.BodyGroup != "" {
		if cc.bodyIdx, err = group(c.BodyGroup, "body_group"); err != nil {
			return nil, err
		}
	}
	switch strings.ToLower(c.Algorithm) {
	case "luhn":
		cc.algorithm = func(body, _ string) bool { return luhnValid(body) }
	case "iban":
		cc.algorithm = func(body, _ string) bool { return ibanValid(body) }
	case "crc32_base62", "crc32_hex", "crc32_dec":
		if c.ChecksumGroup == "" {
			return nil, fmt.Errorf("checksum.checksum_group is required for %s", c.Algorithm)
		}
		if c.Length <= 0 || c.Length > 16 {
			return nil, errors.New("checksum.length must be between 1 and 16 for crc32 algorithms")
		}
		if cc.sumIdx, err = group(c.ChecksumGroup, "checksum_group"); err != nil {
			return nil, err
		}
		render := map[string]func(uint32) string{
			"crc32_base62": base62,
			"crc32_hex":    func(v uint32) string { return fmt.Sprintf("%x", v) },
			"crc32_dec":    func(v uint32) string { return fmt.Sprintf("%d", v) },
		}[strings.ToLower(c.Algorithm)]
		n := c.Length
		cc.algorithm = func(body, sum string) bool {
			return fitWidth(render(crc32.ChecksumIEEE([]byte(body))), n) == sum
		}
	default:
		return nil, fmt.Errorf("checksum.algorithm %q unknown (valid: luhn, iban, crc32_base62, crc32_hex, crc32_dec)", c.Algorithm)
	}
	return cc, nil
}

// valid reports whether the submatch (from FindSubmatchIndex) passes. A
// missing optional capture fails closed: a checksum rule only reports
// candidates whose checksum was actually confirmed.
func (cc *checksumCheck) valid(data []byte, loc []int) bool {
	sub := func(idx int) (string, bool) {
		if idx < 0 {
			return string(data[loc[0]:loc[1]]), true
		}
		if loc[2*idx] < 0 {
			return "", false
		}
		return string(data[loc[2*idx]:loc[2*idx+1]]), true
	}
	body, ok := sub(cc.bodyIdx)
	if !ok {
		return false
	}
	sum := ""
	if cc.sumIdx >= 0 {
		if sum, ok = sub(cc.sumIdx); !ok {
			return false
		}
	}
	return cc.algorithm(body, sum)
}

// base62 uses the 0-9A-Za-z alphabet of GitHub's token checksums.
func base62(v uint32) string {
	const alphabet = "0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz"
	if v == 0 {
		return "0"
	}
	var b []byte
	for v > 0 {
		b = append([]byte{alphabet[v%62]}, b...)
		v /= 62
	}
	return string(b)
}

func fitWidth(s string, n int) string {
	if len(s) >= n {
		return s[len(s)-n:]
	}
	return strings.Repeat("0", n-len(s)) + s
}

func luhnValid(s string) bool {
	var digits []int
	for _, r := range s {
		switch {
		case r >= '0' && r <= '9':
			digits = append(digits, int(r-'0'))
		case r == ' ' || r == '-':
		default:
			return false
		}
	}
	if len(digits) < 2 {
		return false
	}
	sum := 0
	for i := len(digits) - 1; i >= 0; i-- {
		d := digits[i]
		if (len(digits)-1-i)%2 == 1 {
			d *= 2
			if d > 9 {
				d -= 9
			}
		}
		sum += d
	}
	return sum%10 == 0
}

func ibanValid(s string) bool {
	s = strings.ToUpper(strings.ReplaceAll(s, " ", ""))
	if len(s) < 5 || len(s) > 34 {
		return false
	}
	for i, r := range s {
		isL, isD := r >= 'A' && r <= 'Z', r >= '0' && r <= '9'
		if (i < 2 && !isL) || (i >= 2 && i < 4 && !isD) || (!isL && !isD) {
			return false
		}
	}
	rearranged := s[4:] + s[:4]
	rem := 0
	for _, r := range rearranged {
		if r >= 'A' {
			v := int(r-'A') + 10
			rem = (rem*100 + v) % 97
		} else {
			rem = (rem*10 + int(r-'0')) % 97
		}
	}
	return rem == 1
}
