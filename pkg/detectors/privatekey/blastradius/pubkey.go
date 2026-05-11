// Package blastradius derives the public-key half of a PEM private key
// locally and exposes a Subject Public Key Info (SPKI) SHA-256 fingerprint
// that can be looked up against Certificate Transparency logs.
//
// The private key never leaves the process — only the public-key
// fingerprint is suitable for transmission. This mirrors the design of
// trufflesecurity's driftwood (https://github.com/trufflesecurity/driftwood),
// which proved that public-key-only lookups can attribute a leaked key to:
//   - the TLS domains its cert chain covers (Certificate Transparency),
//   - the GitHub users who advertise the matching SSH key.
//
// Only the SPKI SHA-256 path is implemented here. CT-log resolution lives
// in ct.go; the encrypted-PEM unlock path lives in passphrase.go.
package blastradius

import (
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/x509"
	"encoding/hex"
	"encoding/pem"
	"errors"
	"fmt"
	"strings"

	"golang.org/x/crypto/ssh"
)

// PublicKey is the derived-public-key view of a private-key PEM block.
//
// Algorithm is one of "RSA", "EC", "ED25519", "DSA", "OPENSSH", "PGP".
// SPKISHA256Hex is the lowercase hex of sha256(SubjectPublicKeyInfo
// DER) — exactly the value crt.sh exposes at `?spkisha256=`.
// SSHFingerprint is the OpenSSH-style `SHA256:<base64-no-pad>` form
// (matches `ssh-keygen -lf <pub>`) — only set when the input was an
// OPENSSH key. Encrypted is true when the PEM carried a passphrase-
// protected payload that we could not decrypt without one; in that
// case the other fields are zero-valued and the caller may retry via
// TryDecrypt.
type PublicKey struct {
	Algorithm      string
	SPKISHA256Hex  string
	SSHFingerprint string
	Encrypted      bool
}

// ErrNoPEMBlock is returned when the input bytes did not decode as a PEM
// block. Callers handle this softly — a regex match that does not round-
// trip through `pem.Decode` is a regex false positive, not a hard error.
var ErrNoPEMBlock = errors.New("blastradius: no PEM block found")

// ErrEncrypted signals a passphrase-protected PEM. The PublicKey returned
// alongside this error has Encrypted=true; algorithm/fingerprint are
// zero-valued because the key body has not been parsed. Callers that
// want to attempt decryption should hand the raw block to TryDecrypt.
var ErrEncrypted = errors.New("blastradius: PEM is encrypted")

// Derive parses a PEM-encoded private key and returns its public-key
// view. When the PEM is encrypted, Derive returns (PublicKey{Encrypted:
// true}, ErrEncrypted) so the caller can branch into TryDecrypt
// without re-decoding. Any other parse failure yields a typed error.
func Derive(pemBytes []byte) (PublicKey, error) {
	block, _ := pem.Decode(trimNonPEM(pemBytes))
	if block == nil {
		return PublicKey{}, ErrNoPEMBlock
	}
	return deriveBlock(block)
}

// deriveBlock branches on the PEM block type. Encrypted blocks (legacy
// "Proc-Type: 4,ENCRYPTED" header, or the modern "ENCRYPTED PRIVATE
// KEY" type used by OpenSSL 3) short-circuit to ErrEncrypted so the
// caller can retry via TryDecrypt without re-decoding the PEM.
func deriveBlock(block *pem.Block) (PublicKey, error) {
	if isEncrypted(block) {
		return PublicKey{Encrypted: true}, ErrEncrypted
	}
	switch block.Type {
	case "OPENSSH PRIVATE KEY":
		return deriveSSH(block.Bytes)
	case "RSA PRIVATE KEY":
		k, err := x509.ParsePKCS1PrivateKey(block.Bytes)
		if err != nil {
			return PublicKey{}, fmt.Errorf("parse PKCS1: %w", err)
		}
		return spkiOf("RSA", &k.PublicKey)
	case "EC PRIVATE KEY":
		k, err := x509.ParseECPrivateKey(block.Bytes)
		if err != nil {
			return PublicKey{}, fmt.Errorf("parse EC: %w", err)
		}
		return spkiOf("EC", &k.PublicKey)
	case "DSA PRIVATE KEY":
		// FIPS 186-5 retired DSA for signing; modern Go discourages it.
		// We surface the algorithm tag for triage but do not derive a
		// fingerprint — there is no upstream lookup worth running.
		return PublicKey{Algorithm: "DSA"}, nil
	case "PRIVATE KEY":
		k, err := x509.ParsePKCS8PrivateKey(block.Bytes)
		if err != nil {
			return PublicKey{}, fmt.Errorf("parse PKCS8: %w", err)
		}
		return spkiOfAny(k)
	case "ED25519 PRIVATE KEY":
		// Non-standard but seen in practice; treat as raw 32-byte seed.
		if len(block.Bytes) != ed25519.SeedSize {
			return PublicKey{Algorithm: "ED25519"}, nil
		}
		priv := ed25519.NewKeyFromSeed(block.Bytes)
		return spkiOf("ED25519", priv.Public())
	case "PGP PRIVATE KEY BLOCK":
		// PGP keys are out of scope for SPKI/CT correlation; the public
		// key still has meaning for keyserver lookup but that surface
		// is not implemented here. Algorithm tag preserved for triage.
		return PublicKey{Algorithm: "PGP"}, nil
	default:
		return PublicKey{}, fmt.Errorf("blastradius: unsupported PEM type %q", block.Type)
	}
}

// isEncrypted detects both the legacy PKCS#1 encryption header and the
// modern PKCS#8 "ENCRYPTED PRIVATE KEY" block type used by OpenSSL 3 /
// modern keytool exports.
func isEncrypted(block *pem.Block) bool {
	if block.Type == "ENCRYPTED PRIVATE KEY" {
		return true
	}
	if proc, ok := block.Headers["Proc-Type"]; ok && strings.Contains(proc, "ENCRYPTED") {
		return true
	}
	if block.Type == "OPENSSH PRIVATE KEY" && opensshIsEncrypted(block.Bytes) {
		return true
	}
	return false
}

// deriveSSH parses an OpenSSH-format private key and returns both the
// SPKI SHA-256 (for CT-log correlation when the underlying algorithm is
// RSA / ECDSA / Ed25519) and the OpenSSH-style fingerprint (for
// GitHub `<user>.keys` correlation).
func deriveSSH(body []byte) (PublicKey, error) {
	raw, err := ssh.ParseRawPrivateKey(reassembleOpenSSH(body))
	if err != nil {
		return PublicKey{}, fmt.Errorf("parse openssh: %w", err)
	}
	pk, err := spkiOfAny(raw)
	if err != nil {
		return pk, err
	}
	signer, err := ssh.NewSignerFromKey(raw)
	if err == nil {
		pk.SSHFingerprint = ssh.FingerprintSHA256(signer.PublicKey())
	}
	if pk.Algorithm == "" {
		pk.Algorithm = "OPENSSH"
	}
	return pk, nil
}

// reassembleOpenSSH wraps a raw OpenSSH key body back into a PEM
// envelope, which is what `ssh.ParseRawPrivateKey` expects.
func reassembleOpenSSH(body []byte) []byte {
	return pem.EncodeToMemory(&pem.Block{Type: "OPENSSH PRIVATE KEY", Bytes: body})
}

// spkiOf marshals a public key to PKIX SubjectPublicKeyInfo DER, hashes
// it with SHA-256, and returns the hex-encoded fingerprint along with
// the supplied algorithm tag. The hex form (lowercase, no separators)
// matches crt.sh's `?spkisha256=` URL parameter.
func spkiOf(algorithm string, pub any) (PublicKey, error) {
	spki, err := x509.MarshalPKIXPublicKey(pub)
	if err != nil {
		return PublicKey{Algorithm: algorithm}, fmt.Errorf("marshal SPKI: %w", err)
	}
	sum := sha256.Sum256(spki)
	return PublicKey{
		Algorithm:     algorithm,
		SPKISHA256Hex: hex.EncodeToString(sum[:]),
	}, nil
}

// spkiOfAny routes a typed-but-unknown private key through spkiOf. The
// algorithm tag is derived from the dynamic Go type so output stays
// consistent with the explicit-arm paths in deriveBlock.
func spkiOfAny(priv any) (PublicKey, error) {
	switch k := priv.(type) {
	case *rsa.PrivateKey:
		return spkiOf("RSA", &k.PublicKey)
	case *ecdsa.PrivateKey:
		return spkiOf("EC", &k.PublicKey)
	case ed25519.PrivateKey:
		return spkiOf("ED25519", k.Public())
	case *ed25519.PrivateKey:
		return spkiOf("ED25519", k.Public())
	default:
		return PublicKey{}, fmt.Errorf("blastradius: unsupported key type %T", priv)
	}
}

// trimNonPEM strips leading prose so callers can pass a chunk of source
// with a PEM block embedded — `pem.Decode` is strict about leading bytes
// other than the BEGIN line.
func trimNonPEM(b []byte) []byte {
	const marker = "-----BEGIN "
	i := strings.Index(string(b), marker)
	if i <= 0 {
		return b
	}
	return b[i:]
}

// opensshIsEncrypted inspects an OpenSSH private key body for the
// "none" cipher header. False negatives here just route the caller
// through ParseRawPrivateKey where an actual parse error surfaces
// naturally.
func opensshIsEncrypted(body []byte) bool {
	const magic = "openssh-key-v1\x00"
	if len(body) < len(magic)+16 {
		return false
	}
	if string(body[:len(magic)]) != magic {
		return false
	}
	off := len(magic) + 4
	if off+4 > len(body) {
		return false
	}
	return string(body[off:off+4]) != "none"
}
