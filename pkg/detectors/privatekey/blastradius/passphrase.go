// Passphrase wordlist attack against encrypted PEM private keys.
//
// The list is the embedded wordlist.txt (curated from leaked password
// dumps + dev-tooling defaults — see driftwood for the original idea).
// Each candidate is tried against three encryption flavours:
//
//   - legacy PKCS#1 with "Proc-Type: 4,ENCRYPTED" (DEK-Info: AES-…
//     CBC) via x509.DecryptPEMBlock — deprecated in Go but still the
//     dominant flavour in real-world leaks,
//   - modern PKCS#8 "ENCRYPTED PRIVATE KEY" via the bundled OpenSSH
//     decoder (ssh.ParseRawPrivateKeyWithPassphrase routes PBES2
//     envelopes through Go's pkcs8 helper from 1.21+),
//   - OpenSSH v1 keys with bcrypt KDF via the same SSH helper.
//
// On a successful unlock, returns the plaintext PEM bytes (re-armoured
// in the unencrypted equivalent) and the matched passphrase.
package blastradius

import (
	"bufio"
	"crypto/x509"
	_ "embed"
	"encoding/pem"
	"errors"
	"strings"

	"golang.org/x/crypto/ssh"
)

//go:embed wordlist.txt
var embeddedWordlist string

// DefaultPassphrases returns the embedded passphrase candidates. Order
// matters: shortest / most-common candidates come first so the common
// case unlocks within a handful of attempts. Empty lines and lines
// starting with `#` are stripped at load time. The slice is freshly
// allocated per call so callers may safely mutate or extend it (e.g.
// prepend a per-tenant candidate from configuration).
//
// "" is appended last so badly-built CI pipelines that mark a key
// encrypted but actually-empty still unlock.
func DefaultPassphrases() []string {
	var out []string
	scanner := bufio.NewScanner(strings.NewReader(embeddedWordlist))
	for scanner.Scan() {
		line := strings.TrimRight(scanner.Text(), "\r")
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		out = append(out, line)
	}
	out = append(out, "")
	return out
}

// ErrNoPassphraseMatch is returned when the wordlist exhausts without
// unlocking the key. Callers treat this as "encrypted, body unread"
// and emit a finding with pem_encrypted=true / pem_unlocked=false.
var ErrNoPassphraseMatch = errors.New("blastradius: no passphrase in wordlist matched")

// TryDecrypt attempts to decrypt an encrypted PEM private key against
// each candidate passphrase. Returns the plaintext PEM bytes and the
// matched passphrase on success.
func TryDecrypt(pemBytes []byte, candidates []string) ([]byte, string, error) {
	block, _ := pem.Decode(trimNonPEM(pemBytes))
	if block == nil {
		return nil, "", ErrNoPEMBlock
	}
	for _, pw := range candidates {
		if plaintext, ok := tryOne(block, pw); ok {
			return plaintext, pw, nil
		}
	}
	return nil, "", ErrNoPassphraseMatch
}

// tryOne dispatches one (block, passphrase) attempt across the three
// encryption flavours we support. Returns (plaintext PEM, true) on
// the first successful unlock.
func tryOne(block *pem.Block, passphrase string) ([]byte, bool) {
	switch block.Type {
	case "OPENSSH PRIVATE KEY":
		return tryOpenSSH(block, passphrase)
	case "ENCRYPTED PRIVATE KEY":
		return tryPKCS8(block, passphrase)
	default:
		return tryLegacyPEM(block, passphrase)
	}
}

// tryLegacyPEM handles the PKCS#1-flavoured "Proc-Type: 4,ENCRYPTED"
// envelope. Go marked x509.DecryptPEMBlock as deprecated in 1.16 but
// the API still works and remains the only stdlib path for this
// format — the //nolint pin acknowledges the trade-off.
func tryLegacyPEM(block *pem.Block, passphrase string) ([]byte, bool) {
	if proc, ok := block.Headers["Proc-Type"]; !ok || !strings.Contains(proc, "ENCRYPTED") {
		return nil, false
	}
	// x509.DecryptPEMBlock is deprecated (SA1019) but intentional here:
	// blast-radius analysis must crack legacy RFC 1423 encrypted keys to
	// assess exposure. //lint:ignore is the directive standalone
	// staticcheck (CI) honours; //nolint:staticcheck keeps golangci-lint
	// quiet for the same line.
	//lint:ignore SA1019 legacy RFC 1423 PEM decryption is intentional for blast-radius analysis
	plain, err := x509.DecryptPEMBlock(block, []byte(passphrase)) //nolint:staticcheck // SA1019: see //lint:ignore directive above
	if err != nil {
		return nil, false
	}
	out := &pem.Block{Type: strings.TrimPrefix(block.Type, "ENCRYPTED "), Bytes: plain}
	return pem.EncodeToMemory(out), true
}

// tryOpenSSH attempts to unlock an OpenSSH v1 private key using the
// provided passphrase. ssh.ParseRawPrivateKeyWithPassphrase returns a
// distinguished error when the passphrase is wrong; we treat any non-
// nil error as "skip this candidate" rather than introspecting types
// because Go's ssh package returns several wrapped error shapes.
func tryOpenSSH(block *pem.Block, passphrase string) ([]byte, bool) {
	envelope := pem.EncodeToMemory(&pem.Block{Type: block.Type, Bytes: block.Bytes})
	_, err := ssh.ParseRawPrivateKeyWithPassphrase(envelope, []byte(passphrase))
	if err != nil {
		return nil, false
	}
	return envelope, true
}

// tryPKCS8 handles modern OpenSSL 3 / keytool exports of the form
// "ENCRYPTED PRIVATE KEY". The ssh helper routes PBES2 envelopes
// through Go 1.21+'s pkcs8 path; on older runtimes (or unsupported
// cipher suites) the call returns an error and we treat the key as
// "encrypted, unlock-unavailable" rather than misclassifying.
func tryPKCS8(block *pem.Block, passphrase string) ([]byte, bool) {
	envelope := pem.EncodeToMemory(&pem.Block{Type: block.Type, Bytes: block.Bytes})
	_, err := ssh.ParseRawPrivateKeyWithPassphrase(envelope, []byte(passphrase))
	if err != nil {
		return nil, false
	}
	return envelope, true
}

// DeriveWithPassphrase is a convenience wrapper that combines TryDecrypt
// + Derive. Callers that already have an encrypted PEM and want a
// fingerprint without constructing the wordlist twice use this.
func DeriveWithPassphrase(pemBytes []byte, candidates []string) (PublicKey, string, error) {
	plain, pw, err := TryDecrypt(pemBytes, candidates)
	if err != nil {
		return PublicKey{Encrypted: true}, "", err
	}
	pk, derr := Derive(plain)
	if derr != nil {
		return pk, pw, derr
	}
	return pk, pw, nil
}
