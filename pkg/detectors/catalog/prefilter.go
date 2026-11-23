package catalog

import "bytes"

// prefilters attaches hand-written necessary conditions (see
// detectors.Format.Prefilter) to imported rules whose keywords match common
// text, so their regexps are skipped on windows that cannot match.
// TestPrefiltersAreNecessary checks each against its pattern.
var prefilters = map[string]func([]byte) bool{
	// [0-9A-Fa-f]{32}\.[0-9A-Za-z]{16}, keyed upstream on "." alone: it
	// ran on nearly every window and was the costliest catalog format in
	// full-history scans.
	"betterleaks.zai-api-key": hexRunBeforeDot(32),
	// (pa|al)-[-0-9A-Za-z_]{43}, keyed on "pa-"/"al-".
	"betterleaks.voyageai-api-key": literalThenRun([][]byte{[]byte("pa-"), []byte("al-")}, 43, isTokenByte),
	// ...(password|pwd)[\t ]*=[\t ]*\{...\}, keyed on "password"/"pwd",
	// which every config diff contains.
	"kingfisher.connection-string.password.odbc-braced": equalsBrace,
}

// hexRunBeforeDot reports whether data contains at least n consecutive hex
// digits immediately followed by '.'.
func hexRunBeforeDot(n int) func([]byte) bool {
	return func(data []byte) bool {
		run := 0
		for _, c := range data {
			switch {
			case '0' <= c && c <= '9', 'a' <= c && c <= 'f', 'A' <= c && c <= 'F':
				run++
			case c == '.' && run >= n:
				return true
			default:
				run = 0
			}
		}
		return false
	}
}

// literalThenRun reports whether one of lits occurs followed by at least n
// bytes accepted by class.
func literalThenRun(lits [][]byte, n int, class func(byte) bool) func([]byte) bool {
	return func(data []byte) bool {
		for _, lit := range lits {
			for off := 0; ; {
				i := bytes.Index(data[off:], lit)
				if i < 0 {
					break
				}
				start := off + i + len(lit)
				run := 0
				for start+run < len(data) && run < n && class(data[start+run]) {
					run++
				}
				if run >= n {
					return true
				}
				off += i + 1
			}
		}
		return false
	}
}

func isTokenByte(c byte) bool {
	return c == '-' || c == '_' || '0' <= c && c <= '9' || 'a' <= c && c <= 'z' || 'A' <= c && c <= 'Z'
}

// equalsBrace reports whether data contains '=' followed, after optional
// tabs and spaces, by '{'.
func equalsBrace(data []byte) bool {
	for off := 0; ; {
		i := bytes.IndexByte(data[off:], '{')
		if i < 0 {
			return false
		}
		j := off + i - 1
		for j >= 0 && (data[j] == ' ' || data[j] == '\t') {
			j--
		}
		if j >= 0 && data[j] == '=' {
			return true
		}
		off += i + 1
	}
}
