package main

import "testing"

// The three literal samples below are field-for-field the schema
// captured live from `pleno-dlp scan filesystem ... --format json`,
// `trufflehog filesystem ... --json`, and `gitleaks dir ... --report-format
// json` while building this harness against bench/fixtures/synthetic.
// Schema drift in any of the three tools breaks this test, which is the
// point. The Raw/Secret/Match/redacted VALUES are replaced with an
// inert placeholder — parsePlenoDLP/parseTrufflehog/parseGitleaks never
// read those fields (only File and the detector/rule name), so this
// changes nothing under test while keeping a credential-shaped string
// out of source control.
const plenoDLPSample = `[{"detector": "AWS", "verified": false, "verdict": "unverified", "redacted": "REDACTED_SAMPLE_VALUE", "source": {"type": "filesystem", "metadata": {"line": 1, "path": "/corpus/aws-access-key-pair.txt"}}, "extra_data": {}}]`

const trufflehogSample = `{"SourceMetadata":{"Data":{"Filesystem":{"file":"/corpus/mailchimp-api-key.txt","line":1}}},"SourceID":1,"SourceType":15,"SourceName":"trufflehog - filesystem","DetectorType":20,"DetectorName":"Mailchimp","DetectorDescription":"...","DecoderName":"PLAIN","Verified":false,"VerificationFromCache":false,"Raw":"REDACTED_SAMPLE_VALUE","RawV2":"","Redacted":"","ExtraData":{},"StructuredData":null}
`

const gitleaksSample = `[{"RuleID": "algolia-api-key", "Description": "...", "StartLine": 2, "EndLine": 2, "StartColumn": 2, "EndColumn": 51, "Match": "ALGOLIA_ADMIN_KEY=REDACTED_SAMPLE_VALUE", "Secret": "REDACTED_SAMPLE_VALUE", "File": "/corpus/algolia-api-key.txt", "SymlinkFile": "", "Commit": "", "Entropy": 3.45, "Author": "", "Email": "", "Date": "", "Message": "", "Tags": [], "Fingerprint": "x:algolia-api-key:2"}]`

func TestParsePlenoDLP(t *testing.T) {
	got, err := parsePlenoDLP([]byte(plenoDLPSample))
	if err != nil {
		t.Fatalf("parsePlenoDLP: %v", err)
	}
	if len(got) != 1 {
		t.Fatalf("expected 1 finding, got %d", len(got))
	}
	want := finding{Tool: "pleno-dlp", File: "/corpus/aws-access-key-pair.txt", Name: "AWS"}
	if got[0] != want {
		t.Errorf("got %+v, want %+v", got[0], want)
	}
}

func TestParsePlenoDLP_Empty(t *testing.T) {
	got, err := parsePlenoDLP([]byte("[]"))
	if err != nil || len(got) != 0 {
		t.Fatalf("expected 0 findings, nil err; got %v, %v", got, err)
	}
	got, err = parsePlenoDLP(nil)
	if err != nil || len(got) != 0 {
		t.Fatalf("nil input: expected 0 findings, nil err; got %v, %v", got, err)
	}
}

func TestParseTrufflehog(t *testing.T) {
	got, err := parseTrufflehog([]byte(trufflehogSample))
	if err != nil {
		t.Fatalf("parseTrufflehog: %v", err)
	}
	if len(got) != 1 {
		t.Fatalf("expected 1 finding, got %d", len(got))
	}
	want := finding{Tool: "trufflehog", File: "/corpus/mailchimp-api-key.txt", Name: "Mailchimp"}
	if got[0] != want {
		t.Errorf("got %+v, want %+v", got[0], want)
	}
}

func TestParseTrufflehog_BlankLinesIgnored(t *testing.T) {
	got, err := parseTrufflehog([]byte("\n\n" + trufflehogSample + "\n\n"))
	if err != nil {
		t.Fatalf("parseTrufflehog: %v", err)
	}
	if len(got) != 1 {
		t.Fatalf("expected 1 finding, got %d", len(got))
	}
}

func TestParseGitleaks(t *testing.T) {
	got, err := parseGitleaks([]byte(gitleaksSample))
	if err != nil {
		t.Fatalf("parseGitleaks: %v", err)
	}
	if len(got) != 1 {
		t.Fatalf("expected 1 finding, got %d", len(got))
	}
	want := finding{Tool: "gitleaks", File: "/corpus/algolia-api-key.txt", Name: "algolia-api-key"}
	if got[0] != want {
		t.Errorf("got %+v, want %+v", got[0], want)
	}
}

func TestParseGitleaks_NoLeaks(t *testing.T) {
	got, err := parseGitleaks([]byte("[]"))
	if err != nil || len(got) != 0 {
		t.Fatalf("expected 0 findings, nil err; got %v, %v", got, err)
	}
}
