// Package contextextract provides reusable helpers for extracting context
// (tenant IDs, host URLs, etc.) from the surrounding chunk data passed to
// FromData. Many detectors can find the missing verification context within
// the same chunk by scanning nearby bytes for known configuration patterns.
package contextextract

import (
	"bytes"
	"math"
	"regexp"
	"strings"
	"unicode"
)

// uuidPat matches standard 8-4-4-4-12 hex UUIDs.
var uuidPat = regexp.MustCompile(`[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}`)

// FindNearbyUUID scans for a UUID near the anchor position associated with one of the keywords.
func FindNearbyUUID(data []byte, anchorStart, anchorEnd int, keywords []string, maxRadius int) (string, bool) {
	window, offset := extractWindow(data, anchorStart, anchorEnd, maxRadius)
	matches := uuidPat.FindAllIndex(window, -1)
	if len(matches) == 0 {
		return "", false
	}

	// Pre-lower the window for keyword matching.
	lowerWindow := bytes.ToLower(window)
	lowerKeywords := make([][]byte, len(keywords))
	for i, kw := range keywords {
		lowerKeywords[i] = []byte(strings.ToLower(kw))
	}

	type candidate struct {
		uuid string
		dist int
	}
	var best *candidate

	anchorMid := (anchorStart + anchorEnd) / 2

	for _, m := range matches {
		absStart := m[0] + offset
		absEnd := m[1] + offset

		// Skip if this UUID *is* the anchor itself (overlapping).
		if absStart < anchorEnd && absEnd > anchorStart {
			continue
		}

		uuidStr := string(window[m[0]:m[1]])

		// Check that at least one keyword appears within maxRadius of this UUID.
		if !hasNearbyKeyword(lowerWindow, m[0], m[1], lowerKeywords, maxRadius) {
			continue
		}

		dist := distFromAnchor(absStart, absEnd, anchorMid)
		if best == nil || dist < best.dist {
			best = &candidate{uuid: uuidStr, dist: dist}
		}
	}

	if best == nil {
		return "", false
	}
	return best.uuid, true
}

// FindNearbyKeyValue scans for key=value or "key": "value" patterns (case-insensitive key match).
func FindNearbyKeyValue(data []byte, key string, maxRadius int) (string, bool) {
	escapedKey := regexp.QuoteMeta(key)

	// Try JSON pattern first: "key": "value"
	jsonPat := regexp.MustCompile(`(?i)"` + escapedKey + `"\s*:\s*"([^"]*)"`)
	if m := jsonPat.FindSubmatch(data); m != nil {
		return string(m[1]), true
	}

	// Try assignment pattern: key=value, key: value, key="value"
	eqPat := regexp.MustCompile(`(?i)(?:^|[\s;,])` + escapedKey + `\s*[:=]\s*"?([^\s,;"'\r\n]+)"?`)
	if m := eqPat.FindSubmatch(data); m != nil {
		val := string(m[1])
		// Trim trailing quote if we captured one.
		val = strings.TrimRight(val, `"'`)
		return val, true
	}

	return "", false
}

// FindNearbyHost scans for hostnames matching *.<suffix> within maxRadius bytes of the anchor.
func FindNearbyHost(data []byte, anchorStart int, suffix string, maxRadius int) (string, bool) {
	escapedSuffix := regexp.QuoteMeta(suffix)
	pat := regexp.MustCompile(`[a-zA-Z0-9]([a-zA-Z0-9\-]*[a-zA-Z0-9])?(\.[a-zA-Z0-9]([a-zA-Z0-9\-]*[a-zA-Z0-9])?)*` + escapedSuffix)

	window, offset := extractWindow(data, anchorStart, anchorStart, maxRadius)
	matches := pat.FindAllIndex(window, -1)
	if len(matches) == 0 {
		return "", false
	}

	var bestHost string
	bestDist := math.MaxInt64

	for _, m := range matches {
		absStart := m[0] + offset
		absEnd := m[1] + offset
		dist := distFromAnchor(absStart, absEnd, anchorStart)

		host := string(window[m[0]:m[1]])

		// Extend left to capture any leading label characters that the
		// window boundary may have cut. Not necessary with sufficient radius,
		// but be defensive.
		startInData := m[0] + offset
		for startInData > 0 && isHostChar(data[startInData-1]) {
			startInData--
		}
		if startInData != m[0]+offset {
			host = string(data[startInData : m[1]+offset])
		}

		// Trim any leading dots or hyphens.
		host = strings.TrimLeft(host, ".-")

		if dist < bestDist {
			bestHost = host
			bestDist = dist
		}
		_ = absEnd
	}

	if bestHost == "" {
		return "", false
	}
	return bestHost, true
}

// extractWindow returns a subslice of data centered around the anchor with the
// given radius, plus the offset of the window start within data.
func extractWindow(data []byte, anchorStart, anchorEnd, radius int) ([]byte, int) {
	mid := (anchorStart + anchorEnd) / 2
	start := mid - radius
	if start < 0 {
		start = 0
	}
	end := mid + radius
	if end > len(data) {
		end = len(data)
	}
	return data[start:end], start
}

// hasNearbyKeyword checks if any keyword appears within radius bytes of the match.
func hasNearbyKeyword(lowerWindow []byte, matchStart, matchEnd int, lowerKeywords [][]byte, radius int) bool {
	kwStart := matchStart - radius
	if kwStart < 0 {
		kwStart = 0
	}
	kwEnd := matchEnd + radius
	if kwEnd > len(lowerWindow) {
		kwEnd = len(lowerWindow)
	}
	region := lowerWindow[kwStart:kwEnd]
	for _, kw := range lowerKeywords {
		if bytes.Contains(region, kw) {
			return true
		}
	}
	return false
}

// distFromAnchor returns the distance between a match and the anchor midpoint.
func distFromAnchor(matchStart, matchEnd, anchorMid int) int {
	matchMid := (matchStart + matchEnd) / 2
	d := matchMid - anchorMid
	if d < 0 {
		return -d
	}
	return d
}

// isHostChar returns true if b is valid in a hostname label.
func isHostChar(b byte) bool {
	r := rune(b)
	return unicode.IsLetter(r) || unicode.IsDigit(r) || r == '-' || r == '.'
}
