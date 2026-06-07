// Passphrase wordlist attack against encrypted PEM private keys.
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

var ErrNoPassphraseMatch = errors.New("blastradius: no passphrase in wordlist matched")

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

func tryOpenSSH(block *pem.Block, passphrase string) ([]byte, bool) {
	envelope := pem.EncodeToMemory(&pem.Block{Type: block.Type, Bytes: block.Bytes})
	_, err := ssh.ParseRawPrivateKeyWithPassphrase(envelope, []byte(passphrase))
	if err != nil {
		return nil, false
	}
	return envelope, true
}

func tryPKCS8(block *pem.Block, passphrase string) ([]byte, bool) {
	envelope := pem.EncodeToMemory(&pem.Block{Type: block.Type, Bytes: block.Bytes})
	_, err := ssh.ParseRawPrivateKeyWithPassphrase(envelope, []byte(passphrase))
	if err != nil {
		return nil, false
	}
	return envelope, true
}

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
