package git

import (
	"fmt"
	"strconv"
	"strings"
	"time"
)

// parseGitISODate parses git's strict ISO 8601 (%aI) rendering. Git stores
// the author timezone as a raw signed ±HHMM integer and renders it without
// range checks, so real histories contain offsets such as "+518:00"
// (rails 8845ae6, stored as +51800) that time.RFC3339 rejects. Such commits
// must still be scanned, so out-of-range offsets are applied verbatim.
func parseGitISODate(value string) (time.Time, error) {
	if t, err := time.Parse(time.RFC3339, value); err == nil {
		return t, nil
	}
	const layout = "2006-01-02T15:04:05"
	if len(value) < len(layout)+1 {
		return time.Time{}, fmt.Errorf("parsing git date %q: too short", value)
	}
	local, err := time.Parse(layout, value[:len(layout)])
	if err != nil {
		return time.Time{}, fmt.Errorf("parsing git date %q: %w", value, err)
	}
	zone := value[len(layout):]
	sign := 1
	switch zone[0] {
	case '+':
	case '-':
		sign = -1
	default:
		return time.Time{}, fmt.Errorf("parsing git date %q: missing zone sign", value)
	}
	hoursText, minutesText, ok := strings.Cut(zone[1:], ":")
	if !ok || len(minutesText) != 2 || hoursText == "" || len(hoursText) > 4 {
		return time.Time{}, fmt.Errorf("parsing git date %q: malformed zone", value)
	}
	hours, herr := strconv.Atoi(hoursText)
	minutes, merr := strconv.Atoi(minutesText)
	if herr != nil || merr != nil || hours < 0 || minutes < 0 || minutes > 99 {
		return time.Time{}, fmt.Errorf("parsing git date %q: malformed zone", value)
	}
	offset := sign * (hours*3600 + minutes*60)
	return local.Add(-time.Duration(offset) * time.Second).UTC(), nil
}
