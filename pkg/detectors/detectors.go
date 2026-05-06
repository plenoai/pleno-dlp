// Package detectors defines the trufflehog-compatible Detector interface and
// the Result shape returned to the engine. Concrete detectors live under
// pkg/detectors/<provider>/ and self-register in registry.go via init().
package detectors

import "context"

// DetectorType is a stable identifier for each detector. Values are stable
// across releases; new detectors get a new value, never reuse retired ones.
type DetectorType int32

const (
	Unknown DetectorType = iota
	AWS
	GCPServiceAccount
	AzureStorageKey
	GitHub
	GitLab
	SlackBotToken
	SlackWebhook
	OpenAI
	Anthropic
	Stripe
	JWT
	PrivateKeyPEM
	GenericHighEntropy
)

// Result is what a detector emits per match. Mirrors trufflehog's Result so
// detectors can be ported in either direction.
type Result struct {
	DetectorType    DetectorType
	Verified        bool
	VerificationErr error
	// Raw is the matched secret bytes. Never logged in plaintext.
	Raw []byte
	// RawV2 is a paired secret (e.g. AWS secret access key when Raw is the
	// access key id). Empty when single-secret.
	RawV2 []byte
	// Redacted is a safe-to-display rendering (prefix + ellipsis).
	Redacted  string
	ExtraData map[string]string
}

// Detector is the trufflehog-compatible detector contract. Keywords gates the
// expensive FromData step: the engine skips chunks containing none of the
// returned strings (case-insensitive substring match).
type Detector interface {
	Keywords() []string
	FromData(ctx context.Context, verify bool, data []byte) ([]Result, error)
	Type() DetectorType
}

// Verifier is optionally implemented by detectors that can confirm a candidate
// secret with the upstream provider. Engine will call Verify only when the
// caller requested verification.
type Verifier interface {
	Verify(ctx context.Context, secret string) (bool, error)
}
