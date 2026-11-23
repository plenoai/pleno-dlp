package detectors

// FormatLeadForTest exposes the compiled leading literal ("" when the
// format takes the plain regexp path). Test-only (export_test.go).
func FormatLeadForTest(f *Format) string {
	if _, err := f.Compile(); err != nil || f.anchored == nil {
		return ""
	}
	return string(f.lead)
}

// FormatFindAllForTest runs the format's matcher exactly as
// MatchFormatsAt does. Test-only (export_test.go).
func FormatFindAllForTest(f *Format, data []byte) [][]int {
	if _, err := f.Compile(); err != nil {
		return nil
	}
	var lower asciiScratch
	defer lower.release()
	return append([][]int(nil), f.findAll(data, &lower)...)
}

// KeywordHaystackForTest exposes keywordHaystack. Test-only (export_test.go).
func KeywordHaystackForTest(data []byte) []byte {
	var lower asciiScratch
	return append([]byte(nil), keywordHaystack(data, &lower)...)
}
