package feedback

import (
	"fmt"
	"net/url"
	"strings"
)

const (
	intakeReportSchemaV1 = "pleno-dlp.report/v1"
	intakeReportSchemaV2 = "pleno-dlp.report/v2"
	intakeReportKind     = "feedback"
	intakeFalsePositive  = "false-positive"
)

// intakeReport is the HTTP envelope accepted by plenoai.com/workers/intake.
// It is intentionally distinct from Report, which remains the local spool
// format and the custom-relay contract.
type intakeReport struct {
	Schema      string   `json:"schema"`
	Kind        string   `json:"kind"`
	Fingerprint string   `json:"fingerprint"`
	Version     string   `json:"version"`
	Commit      string   `json:"commit"`
	GOOS        string   `json:"goos"`
	GOARCH      string   `json:"goarch"`
	GoVersion   string   `json:"go_version"`
	Command     string   `json:"command"`
	Flags       []string `json:"flags"`
	Message     string   `json:"message"`
	Match       *Match   `json:"match,omitempty"`
}

// usesIntakeProtocol recognizes only the configured intake URL, allowing URL
// case and an explicit default HTTPS port but not a different path or query.
func usesIntakeProtocol(endpoint string) bool {
	u, err := url.Parse(endpoint)
	if err != nil || u.User != nil || u.Opaque != "" || u.RawQuery != "" || u.ForceQuery || u.Fragment != "" || u.RawFragment != "" || strings.Contains(endpoint, "#") {
		return false
	}
	if !strings.EqualFold(u.Scheme, "https") {
		return false
	}
	host := strings.ToLower(u.Host)
	if host != "intake.plenoai.com" && host != "intake.plenoai.com:443" {
		return false
	}
	return u.EscapedPath() == "/v1/pleno-dlp"
}

func intakeReportFor(report Report) (intakeReport, error) {
	out := intakeReport{
		Fingerprint: report.Fingerprint,
		Version:     report.Version,
		Commit:      report.Commit,
		GOOS:        report.GOOS,
		GOARCH:      report.GOARCH,
		GoVersion:   report.GoVersion,
		Command:     report.Command,
		Flags:       report.Flags,
		Message:     report.Message,
	}
	if out.Flags == nil {
		out.Flags = []string{}
	}
	switch report.Schema {
	case Schema:
		if report.Match != nil {
			return intakeReport{}, fmt.Errorf("feedback: schema %q cannot contain match context", Schema)
		}
		out.Schema = intakeReportSchemaV1
		out.Kind = intakeReportKind
	case SchemaV2:
		if report.Match == nil {
			return intakeReport{}, fmt.Errorf("feedback: schema %q requires match context", SchemaV2)
		}
		if err := validateMatch(*report.Match); err != nil {
			return intakeReport{}, err
		}
		if len(report.Match.Detector) > 64 {
			return intakeReport{}, fmt.Errorf("feedback: intake detector name exceeds 64 characters")
		}
		match := *report.Match
		out.Schema = intakeReportSchemaV2
		out.Kind = intakeFalsePositive
		out.Match = &match
	default:
		return intakeReport{}, fmt.Errorf("feedback: schema %q is not supported", report.Schema)
	}
	return out, nil
}
