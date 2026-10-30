package feedback

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"regexp"
	"runtime"
	"strings"
	"time"

	"github.com/plenoai/pleno-dlp/pkg/detectors"
	"github.com/plenoai/pleno-dlp/pkg/telemetry/crash"
)

// Schema identifies the local feedback spool format. Built-in intake requests
// use the separate pleno-dlp.report/v1 or /v2 envelope.
const Schema = "pleno-dlp.feedback/v1"

// SchemaV2 adds a selected scan match without adding the matched raw bytes.
const SchemaV2 = "pleno-dlp.feedback/v2"

// MaxReportBytes bounds the marshalled report so a very long message cannot
// turn the relay into a bulk upload channel.
const MaxReportBytes = crash.MaxReportBytes

// truncatedMarker terminates a message that was cut to fit MaxReportBytes.
const truncatedMarker = "\n...[truncated]"

// inputLimit caps the raw message before redaction, leaving room for the
// report envelope so the marshalled result stays under MaxReportBytes.
const inputLimit = MaxReportBytes - 1<<10

var digitsRe = regexp.MustCompile(`[0-9]+`)

// Report is the complete feedback payload. Fields are an allowlist: anything
// not declared here is never collected.
type Report struct {
	Schema      string    `json:"schema"`
	Fingerprint string    `json:"fingerprint"`
	Version     string    `json:"version"`
	Commit      string    `json:"commit"`
	GOOS        string    `json:"goos"`
	GOARCH      string    `json:"goarch"`
	GoVersion   string    `json:"go_version"`
	Command     string    `json:"command"`
	Flags       []string  `json:"flags"`
	Message     string    `json:"message"`
	CreatedAt   time.Time `json:"created_at"`
	Match       *Match    `json:"match,omitempty"`
}

// Match is the minimal scan context needed to reproduce a reported finding.
// Hashes identify the raw values without retaining or transmitting them.
type Match struct {
	Detector  string `json:"detector"`
	Redacted  string `json:"redacted"`
	RawHash   string `json:"raw_hash"`
	RawV2Hash string `json:"raw_v2_hash,omitempty"`
}

// Build assembles a redacted, fingerprinted, size-bounded report from the
// operator's message. The message is run through the same redactor crash
// reports use, so a secret pasted into feedback never leaves the machine.
func Build(message string, meta crash.Meta, red *crash.Redactor, now time.Time) Report {
	// Cap the raw message before redaction. Redaction can collapse a long
	// body into a short placeholder (a 32 KiB run of one character becomes
	// "[TOKEN]"), so bounding only the redacted text would leave a huge
	// input with no truncation marker and no size guarantee.
	if len(message) > inputLimit {
		message = cutRunes(message, inputLimit) + truncatedMarker
	}
	msg := message
	command := meta.Command
	if red != nil {
		msg = red.Redact(message)
		command = red.Redact(meta.Command)
	}
	flags := meta.Flags
	if flags == nil {
		flags = []string{}
	}
	r := Report{
		Schema:      Schema,
		Fingerprint: Fingerprint(msg, command),
		Version:     meta.Version,
		Commit:      meta.Commit,
		GOOS:        runtime.GOOS,
		GOARCH:      runtime.GOARCH,
		GoVersion:   runtime.Version(),
		Command:     command,
		Flags:       flags,
		Message:     msg,
		CreatedAt:   now.UTC().Truncate(time.Minute),
	}
	bound(&r)
	return r
}

// BuildWithMatch creates a v2 report from one selected scan result. The raw
// bytes are used only to validate the redacted display and compute hashes.
func BuildWithMatch(message string, meta crash.Meta, red *crash.Redactor, now time.Time, result detectors.Result) (Report, error) {
	if result.DetectorType == detectors.Unknown || len(result.Raw) == 0 && len(result.RawV2) == 0 {
		return Report{}, fmt.Errorf("feedback: match requires a known detector and raw value")
	}
	match := Match{
		Detector:  result.DetectorType.String(),
		Redacted:  result.SafeRedacted(),
		RawHash:   hashRaw(result.Raw),
		RawV2Hash: hashRaw(result.RawV2),
	}
	if err := validateMatch(match); err != nil {
		return Report{}, err
	}
	if red == nil {
		red = &crash.Redactor{}
	}
	match.Redacted = red.Redact(match.Redacted)
	if match.Redacted == "" {
		return Report{}, fmt.Errorf("feedback: match redacted to empty text")
	}
	r := Build(message, meta, red, now)
	r.Schema = SchemaV2
	r.Match = &match
	r.Fingerprint = Fingerprint(r.Message, strings.Join([]string{r.Command, match.Detector, match.RawHash, match.RawV2Hash}, "\n"))
	bound(&r)
	return r, nil
}

func hashRaw(raw []byte) string {
	if len(raw) == 0 {
		return ""
	}
	sum := sha256.Sum256(raw)
	return hex.EncodeToString(sum[:])
}

func validateMatch(match Match) error {
	if match.Detector == "" || len(match.Detector) > 128 || !detectorNameRe.MatchString(match.Detector) {
		return fmt.Errorf("feedback: match detector is invalid")
	}
	if match.Redacted == "" || len(match.Redacted) > maxMatchRedactedBytes {
		return fmt.Errorf("feedback: match redacted text is empty or too large")
	}
	if !validRawHash(match.RawHash) && !validRawHash(match.RawV2Hash) {
		return fmt.Errorf("feedback: match requires a SHA-256 raw hash")
	}
	if match.RawHash != "" && !validRawHash(match.RawHash) || match.RawV2Hash != "" && !validRawHash(match.RawV2Hash) {
		return fmt.Errorf("feedback: match raw hash must be 64 lowercase hexadecimal characters")
	}
	return nil
}

const maxMatchRedactedBytes = 8 << 10

var detectorNameRe = regexp.MustCompile(`^[A-Za-z][A-Za-z0-9_]*$`)

func validRawHash(hash string) bool {
	if len(hash) != sha256.Size*2 || strings.ToLower(hash) != hash {
		return false
	}
	_, err := hex.DecodeString(hash)
	return err == nil
}

// Fingerprint groups identical feedback independent of per-run values:
// sha256 over the digit-normalized message and the command, truncated to 16
// hex chars.
func Fingerprint(message, command string) string {
	h := sha256.New()
	h.Write([]byte(digitsRe.ReplaceAllString(message, "N")))
	h.Write([]byte{'\n'})
	h.Write([]byte(command))
	return hex.EncodeToString(h.Sum(nil))[:16]
}

// bound truncates the message tail until the marshalled report fits
// MaxReportBytes.
func bound(r *Report) {
	for {
		b, err := json.Marshal(r)
		if err != nil || len(b) <= MaxReportBytes {
			return
		}
		over := len(b) - MaxReportBytes + len(truncatedMarker) + 64
		if len(r.Message) > over {
			r.Message = cutRunes(r.Message, len(r.Message)-over) + truncatedMarker
			continue
		}
		r.Message = truncatedMarker
		return
	}
}

// cutRunes truncates s to at most n bytes without splitting a UTF-8 rune.
func cutRunes(s string, n int) string {
	if n <= 0 {
		return ""
	}
	if n >= len(s) {
		return s
	}
	for n > 0 && s[n]&0xC0 == 0x80 {
		n--
	}
	return s[:n]
}
