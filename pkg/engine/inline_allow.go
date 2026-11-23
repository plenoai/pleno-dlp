package engine

import "bytes"

// Inline pragmas. A finding is inline-allowed when the line that holds the
// start or the end of the secret contains a same-line token, or the line
// immediately before the secret's first line contains a next-line token.
// The kingfisher and gitleaks spellings are accepted so repositories
// migrating from those scanners keep their existing annotations.
var (
	inlineSameLineTokens = [][]byte{
		[]byte("pleno-dlp:allow"),
		[]byte("kingfisher:ignore"),
		[]byte("gitleaks:allow"),
	}
	inlineNextLineTokens = [][]byte{
		[]byte("pleno-dlp:allow-next-line"),
	}
)

// inlineAllowedIn reports whether the first occurrence of raw in data is
// covered by an inline pragma.
func inlineAllowedIn(data, raw []byte, extra ...[]byte) bool {
	if len(raw) == 0 || len(data) == 0 {
		return false
	}
	idx := bytes.Index(data, raw)
	if idx < 0 {
		return false
	}
	return inlineAllowedAt(data, idx, idx+len(raw), extra...)
}

// inlineAllowedAt reports whether the secret spanning data[start:end] is
// covered by an inline pragma.
// extra holds operator-supplied same-line tokens (Options.InlineAllowTokens).
func inlineAllowedAt(data []byte, start, end int, extra ...[]byte) bool {
	if start < 0 || end > len(data) || start > end {
		return false
	}
	firstStart := lineStart(data, start)
	if sameLine(data[firstStart:lineEnd(data, start)], extra) {
		return true
	}
	if end > start {
		last := end - 1
		if sameLine(data[lineStart(data, last):lineEnd(data, last)], extra) {
			return true
		}
	}
	if firstStart > 0 {
		prevEnd := firstStart - 1 // the '\n' terminating the previous line
		if containsAny(data[lineStart(data, prevEnd):prevEnd], inlineNextLineTokens) {
			return true
		}
	}
	return false
}

func lineStart(data []byte, i int) int {
	if i > len(data) {
		i = len(data)
	}
	return bytes.LastIndexByte(data[:i], '\n') + 1
}

func lineEnd(data []byte, i int) int {
	if i >= len(data) {
		return len(data)
	}
	if j := bytes.IndexByte(data[i:], '\n'); j >= 0 {
		return i + j
	}
	return len(data)
}

func containsAny(line []byte, tokens [][]byte) bool {
	for _, t := range tokens {
		if bytes.Contains(line, t) {
			return true
		}
	}
	return false
}

func sameLine(line []byte, extra [][]byte) bool {
	return containsAny(line, inlineSameLineTokens) || containsAny(line, extra)
}

// compileInlineTokens drops empty tokens so a blank --inline-allow-token
// can never match every line.
func compileInlineTokens(tokens []string) [][]byte {
	var out [][]byte
	for _, t := range tokens {
		if t != "" {
			out = append(out, []byte(t))
		}
	}
	return out
}
