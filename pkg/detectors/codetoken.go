package detectors

import (
	"regexp"
	"strings"
)

// wordSecretTypes are the detectors whose secrets are human-chosen
// passwords or config values that may legitimately be word-shaped
// (a dictionary-word password in a config file or a netrc entry). The
// engine never applies LooksLikeCodeToken to their findings: their own
// grammars already decide what is a literal, and a dictionary word is a
// plausible password.
var wordSecretTypes = map[DetectorType]struct{}{
	HardcodedPassword:   {},
	Pgpass:              {},
	Netrc:               {},
	GitCredentialsURL:   {},
	PHPConfigSecret:     {},
	FileZillaXML:        {},
	JetBrainsWebServers: {},
	Esmtprc:             {},
	NpmrcAuth:           {},
	DjangoConfigSecret:  {},
	JSLoginCallSecret:   {},
	Redis:               {},
	Postgres:            {},
	MySQL:               {},
	MongoDB:             {},
	RabbitMQ:            {},
	Kafka:               {},
	BasicAuth:           {},
	SMTP:                {},
}

// AcceptsWordSecrets reports whether t's findings may be word-shaped
// (see wordSecretTypes).
func AcceptsWordSecrets(t DetectorType) bool {
	_, ok := wordSecretTypes[t]
	return ok
}

var (
	// A path segment: a lower-case-led identifier word, optionally
	// camelCased, optionally with dotted/hyphenated suffixes
	// (`pleno-dlp`, `currentUser.json`).
	pathSegmentRe = regexp.MustCompile(`^[a-z][a-z0-9]*(?:[A-Z][a-z0-9]+)*(?:[._-][a-zA-Z0-9]+)*$`)
	// SCREAMING_SNAKE environment-variable names (`OPF_SECRET`).
	envNameRe = regexp.MustCompile(`^[A-Z][A-Z0-9]*(?:_[A-Z0-9]+)+$`)
	// One word of an identifier: an acronym run not followed by a lower
	// case letter, or a capitalised / lower-case word.
	identWordRe = regexp.MustCompile(`[A-Z]+(?:[a-z]+)?|[a-z]+`)
)

// LooksLikeCodeToken reports whether raw is shaped like a source-code
// token rather than key material: an import or file path whose segments
// are words (`dlp/pkg/detectors/wasabi`), a dotted selector
// (`detectors.CloudBees.String`), an environment-variable name
// (`OPF_SECRET`), or a digit-free identifier made of pronounceable words
// joined by camelCase, hyphens, or underscores (`SlackUserToken`,
// `context-required`, `Betterleaks`).
//
// Context-window detectors pair a broad charset regex with a provider
// keyword near the match (#943). On source files that mention the
// provider (registries, import blocks, doc comments) the keyword window
// covers identifiers, and the charset regex accepts them. Randomly
// generated keys mix digits and cases without forming words, so they
// fail every branch here: a lower-case base64 run long enough to match
// is vanishingly rare, and letter-only random strings contain runs with
// no vowel (`Sfl`, `Kxw`).
func LooksLikeCodeToken(raw []byte) bool {
	s := strings.Trim(string(raw), "-_./")
	if len(s) < 2 {
		return false
	}
	if envNameRe.MatchString(s) {
		return true
	}
	if strings.ContainsRune(s, '/') {
		segs := strings.Split(s, "/")
		if len(segs) < 2 {
			return false
		}
		for _, seg := range segs {
			if !pathSegmentRe.MatchString(seg) || (len(seg) > 4 && !hasVowel(seg)) {
				return false
			}
		}
		return true
	}
	if strings.ContainsAny(s, "0123456789") {
		return false
	}
	for _, part := range strings.FieldsFunc(s, func(r rune) bool { return r == '.' || r == '-' || r == '_' }) {
		if isShortLowerWord(part) {
			// Abbreviations such as `dlp`, `pkg`, `cmd` in kebab names.
			continue
		}
		if !isWordIdentifier(part) {
			return false
		}
	}
	return true
}

// isWordIdentifier reports whether s is letters only and every word of
// its camelCase split is pronounceable: lower-case runs carry a vowel,
// and all-capital runs are acronym-length.
func isWordIdentifier(s string) bool {
	if s == "" {
		return false
	}
	for i := 0; i < len(s); i++ {
		c := s[i]
		if !(c >= 'a' && c <= 'z' || c >= 'A' && c <= 'Z') {
			return false
		}
	}
	words := identWordRe.FindAllString(s, -1)
	if strings.Join(words, "") != s {
		return false
	}
	short, long := 0, 0
	for _, w := range words {
		lowerRun := strings.TrimLeft(w, "ABCDEFGHIJKLMNOPQRSTUVWXYZ")
		upperRun := len(w) - len(lowerRun)
		switch {
		case lowerRun == "":
			if upperRun > 5 {
				return false
			}
		case hasVowel(lowerRun) && upperRun <= 6:
			long++
		case len(w) <= 3:
			// Abbreviations inside camelCase names (`pdfObjHeader`).
			short++
		default:
			return false
		}
	}
	if long == 0 || short > long+1 {
		return false
	}
	return true
}

func isShortLowerWord(s string) bool {
	if len(s) == 0 || len(s) > 4 {
		return false
	}
	for i := 0; i < len(s); i++ {
		if s[i] < 'a' || s[i] > 'z' {
			return false
		}
	}
	return true
}

func hasVowel(s string) bool {
	return strings.ContainsAny(strings.ToLower(s), "aeiouy")
}
