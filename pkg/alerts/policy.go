package alerts

import (
	"fmt"
	"net/url"
	"strings"
)

// On selects when alerts are delivered.
type On string

const (
	// OnFindings delivers only when the scan produced at least one finding.
	OnFindings On = "findings"
	// OnAlways delivers on every scan, including clean runs (heartbeat).
	OnAlways On = "always"
)

// ParseOn validates --alert-on.
func ParseOn(s string) (On, error) {
	switch On(strings.ToLower(strings.TrimSpace(s))) {
	case "", OnFindings:
		return OnFindings, nil
	case OnAlways:
		return OnAlways, nil
	}
	return "", fmt.Errorf("--alert-on: unknown value %q (valid: findings, always)", s)
}

// FindingFilter restricts which findings a sink reports, on top of the
// minimum severity.
type FindingFilter string

const (
	FilterAll             FindingFilter = "all"
	FilterExcludeInactive FindingFilter = "exclude-inactive"
	FilterOnlyActive      FindingFilter = "only-active"
	FilterAccessMapOnly   FindingFilter = "access-map-only"
)

// ParseFindingFilter validates --alert-finding-filter.
func ParseFindingFilter(s string) (FindingFilter, error) {
	switch f := FindingFilter(strings.ToLower(strings.TrimSpace(s))); f {
	case "":
		return FilterAll, nil
	case FilterAll, FilterExcludeInactive, FilterOnlyActive, FilterAccessMapOnly:
		return f, nil
	}
	return "", fmt.Errorf("--alert-finding-filter: unknown value %q (valid: all, exclude-inactive, only-active, access-map-only)", s)
}

// keep reports whether a finding with the given verdict and access-map
// presence passes the filter. "Inactive" means the provider affirmatively
// rejected the credential (verdict unverified with a verification attempt);
// indeterminate findings are never treated as inactive.
func (f FindingFilter) keep(verdict string, attempted, accessMap bool) bool {
	switch f {
	case FilterExcludeInactive:
		return !(attempted && verdict == "unverified")
	case FilterOnlyActive:
		return verdict == "verified"
	case FilterAccessMapOnly:
		return verdict == "verified" && accessMap
	}
	return true
}

// Detail controls how much per-finding detail chat payloads render.
type Detail string

const (
	DetailAuto    Detail = "auto"
	DetailSummary Detail = "summary"
	DetailFull    Detail = "detail"
	// autoSummaryThreshold is the filtered finding count above which
	// DetailAuto collapses to DetailSummary.
	autoSummaryThreshold = 25
)

// ParseDetail validates --alert-detail.
func ParseDetail(s string) (Detail, error) {
	switch d := Detail(strings.ToLower(strings.TrimSpace(s))); d {
	case "":
		return DetailAuto, nil
	case DetailAuto, DetailSummary, DetailFull:
		return d, nil
	}
	return "", fmt.Errorf("--alert-detail: unknown value %q (valid: auto, summary, detail)", s)
}

func (d Detail) resolve(n int) Detail {
	if d == DetailAuto || d == "" {
		if n > autoSummaryThreshold {
			return DetailSummary
		}
		return DetailFull
	}
	return d
}

// ParseReportURL validates --alert-report-url: an absolute http(s) URL with
// a host. Empty is allowed (no link).
func ParseReportURL(s string) (string, error) {
	s = strings.TrimSpace(s)
	if s == "" {
		return "", nil
	}
	u, err := url.Parse(s)
	if err != nil || u.Host == "" || (u.Scheme != "https" && u.Scheme != "http") {
		return "", fmt.Errorf("--alert-report-url: must be an absolute http(s) URL")
	}
	return u.String(), nil
}

// Policy decides whether and what to deliver after the scan.
type Policy struct {
	On           On
	PreventEmpty bool
	Detail       Detail
	ReportURL    string
}

// ShouldSend reports whether a summary with filtered findings, from a scan
// that produced scanTotal findings overall, should be delivered.
// --alert-on always is a heartbeat and always posts so silence keeps
// meaning "the scan never ran".
func (p Policy) ShouldSend(filtered, scanTotal int) bool {
	if p.On == OnAlways {
		return true
	}
	if scanTotal == 0 {
		return false
	}
	return filtered > 0 || !p.PreventEmpty
}

// Apply stamps the policy's detail and report URL onto s.
func (p Policy) Apply(s Summary) Summary {
	s.Detail = string(p.Detail.resolve(len(s.Findings)))
	s.ReportURL = p.ReportURL
	return s
}
