package aws

import (
	"encoding/base32"
	"encoding/binary"
	"fmt"
	"strings"
	"sync"
)

// builtinSkipAccounts are AWS account IDs that host canary/honey tokens
// (Thinkst canarytokens.org). Calling sts:GetCallerIdentity with such a key
// fires the canary, so verification is never attempted. The list mirrors
// mongodb/kingfisher and is not exhaustive; operators extend it with
// --skip-aws-account / --skip-aws-account-file.
var builtinSkipAccounts = []string{
	"052310077262", "171436882533", "528757803018", "534261010715",
	"538784191382", "595918472158", "729780141977", "893192397702",
	"992382622183",
}

var (
	skipMu       sync.RWMutex
	skipAccounts = newSkipSet(nil)
)

func newSkipSet(extra []string) map[string]struct{} {
	m := make(map[string]struct{}, len(builtinSkipAccounts)+len(extra))
	for _, id := range builtinSkipAccounts {
		m[id] = struct{}{}
	}
	for _, id := range extra {
		m[id] = struct{}{}
	}
	return m
}

// SetSkipAccounts replaces the operator-supplied skip list (the built-in
// canary list always applies). IDs must be 12 digits.
func SetSkipAccounts(ids []string) error {
	clean := make([]string, 0, len(ids))
	for _, id := range ids {
		id = strings.TrimSpace(id)
		if id == "" {
			continue
		}
		if len(id) != 12 || strings.Trim(id, "0123456789") != "" {
			return fmt.Errorf("invalid AWS account ID %q (want 12 digits)", id)
		}
		clean = append(clean, id)
	}
	skipMu.Lock()
	skipAccounts = newSkipSet(clean)
	skipMu.Unlock()
	return nil
}

// IsSkippedAccount reports whether id is on the canary skip list.
func IsSkippedAccount(id string) bool {
	skipMu.RLock()
	defer skipMu.RUnlock()
	_, ok := skipAccounts[id]
	return ok
}

var keyIDEncoding = base32.StdEncoding.WithPadding(base32.NoPadding)

// AccountFromKeyID derives the owning 12-digit account number from an
// access key ID offline (no network). Legacy keys whose fifth character is
// I or J do not encode the account and return ok=false.
func AccountFromKeyID(keyID string) (string, bool) {
	if len(keyID) < 5 || keyID[4] == 'I' || keyID[4] == 'J' {
		return "", false
	}
	dec, err := keyIDEncoding.DecodeString(strings.ToUpper(keyID[4:]))
	if err != nil || len(dec) < 6 {
		return "", false
	}
	var b [8]byte
	copy(b[2:], dec[:6])
	n := (binary.BigEndian.Uint64(b[:]) & 0x7FFFFFFFFF80) >> 7
	return fmt.Sprintf("%012d", n), true
}
