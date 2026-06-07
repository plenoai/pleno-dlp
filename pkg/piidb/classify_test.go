package piidb

import (
	"testing"

	"github.com/plenoai/pleno-dlp/pkg/detectors"
	"github.com/plenoai/pleno-dlp/pkg/engine"
	"github.com/plenoai/pleno-dlp/pkg/sources"
)

func piiFinding(chunk *sources.Chunk) engine.Finding {
	return engine.Finding{
		Result: detectors.Result{
			DetectorType: detectors.PIIAnonymize,
			Severity:     detectors.SeverityMedium,
			Raw:          []byte("test@example.com"),
			ExtraData:    map[string]string{"finding_class": "pii", "pii_kind": "EMAIL_ADDRESS"},
		},
		Chunk:    chunk,
		Detector: detectors.PIIAnonymize,
	}
}

func secretFinding(chunk *sources.Chunk) engine.Finding {
	return engine.Finding{
		Result: detectors.Result{
			DetectorType: detectors.AWS,
			Severity:     detectors.SeverityHigh,
			Raw:          []byte("AKIAIOSFODNN7EXAMPLE"),
			ExtraData:    map[string]string{},
		},
		Chunk:    chunk,
		Detector: detectors.AWS,
	}
}

func fsChunk(path string) *sources.Chunk {
	return &sources.Chunk{
		SourceType: sources.SourceFilesystem,
		SourceMetadata: sources.Metadata{
			Filesystem: &sources.FilesystemMeta{Path: path},
		},
	}
}

func s3Chunk(bucket, key string) *sources.Chunk {
	return &sources.Chunk{
		SourceType: sources.SourceS3,
		SourceMetadata: sources.Metadata{
			S3: &sources.S3Meta{Bucket: bucket, Key: key},
		},
	}
}

func slackChunk(channel, ts string) *sources.Chunk {
	return &sources.Chunk{
		SourceType: sources.SourceSlack,
		SourceMetadata: sources.Metadata{
			Slack: &sources.SlackMeta{Channel: channel, Timestamp: ts},
		},
	}
}

// TestClassify_IsolatedPII_NoEscalation verifies that isolated
// incidental PII (below threshold) stays at SeverityMedium.
func TestClassify_IsolatedPII_NoEscalation(t *testing.T) {
	findings := []engine.Finding{
		piiFinding(fsChunk("/app/config.yml")),
		piiFinding(fsChunk("/app/README.md")),
	}
	results := Classify(findings)
	for i, r := range results {
		if r.IsCandidate {
			t.Errorf("finding[%d]: unexpected PIIDB candidate for isolated PII", i)
		}
	}
}

// TestClassify_ContainerDensity_Unstructured verifies that 3+ PII
// findings in the same unstructured file triggers escalation to High.
func TestClassify_ContainerDensity_Unstructured(t *testing.T) {
	chunk := fsChunk("/app/notes.txt")
	findings := []engine.Finding{
		piiFinding(chunk),
		piiFinding(chunk),
		piiFinding(chunk),
	}
	results := Classify(findings)
	for i, r := range results {
		if !r.IsCandidate {
			t.Fatalf("finding[%d]: expected PIIDB candidate", i)
		}
		if r.NewSeverity != detectors.SeverityHigh {
			t.Errorf("finding[%d]: Severity = %v, want High", i, r.NewSeverity)
		}
		if r.Scope != "container" {
			t.Errorf("finding[%d]: Scope = %q, want container", i, r.Scope)
		}
		if r.Count != 3 {
			t.Errorf("finding[%d]: Count = %d, want 3", i, r.Count)
		}
	}
}

// TestClassify_ContainerDensity_Structured verifies that structured
// formats (csv) get the format bonus: 2 findings in a .csv trigger
// escalation (threshold reduced from 3 to 2).
func TestClassify_ContainerDensity_Structured(t *testing.T) {
	chunk := fsChunk("/data/customers.csv")
	findings := []engine.Finding{
		piiFinding(chunk),
		piiFinding(chunk),
	}
	results := Classify(findings)
	for i, r := range results {
		if !r.IsCandidate {
			t.Fatalf("finding[%d]: expected PIIDB candidate for structured format", i)
		}
		if r.NewSeverity != detectors.SeverityHigh {
			t.Errorf("finding[%d]: Severity = %v, want High", i, r.NewSeverity)
		}
		if r.Format != "csv" {
			t.Errorf("finding[%d]: Format = %q, want csv", i, r.Format)
		}
	}
}

// TestClassify_ContainerDensity_Structured_Critical verifies that 5+
// findings in a structured file escalates to Critical.
func TestClassify_ContainerDensity_Structured_Critical(t *testing.T) {
	chunk := fsChunk("/data/users.sql")
	findings := make([]engine.Finding, 5)
	for i := range findings {
		findings[i] = piiFinding(chunk)
	}
	results := Classify(findings)
	for i, r := range results {
		if !r.IsCandidate {
			t.Fatalf("finding[%d]: expected PIIDB candidate", i)
		}
		if r.NewSeverity != detectors.SeverityCritical {
			t.Errorf("finding[%d]: Severity = %v, want Critical", i, r.NewSeverity)
		}
	}
}

// TestClassify_ContainerDensity_Unstructured_Critical verifies that
// 10+ findings in unstructured text escalates to Critical.
func TestClassify_ContainerDensity_Unstructured_Critical(t *testing.T) {
	chunk := fsChunk("/var/log/app.log")
	findings := make([]engine.Finding, 10)
	for i := range findings {
		findings[i] = piiFinding(chunk)
	}
	results := Classify(findings)
	for i, r := range results {
		if !r.IsCandidate {
			t.Fatalf("finding[%d]: expected PIIDB candidate", i)
		}
		if r.NewSeverity != detectors.SeverityCritical {
			t.Errorf("finding[%d]: Severity = %v, want Critical", i, r.NewSeverity)
		}
	}
}

// TestClassify_ParentDensity verifies that 5+ PII findings across
// files in the same directory triggers parent-density escalation.
func TestClassify_ParentDensity(t *testing.T) {
	findings := make([]engine.Finding, 5)
	for i := range findings {
		findings[i] = piiFinding(fsChunk("/data/exports/file" + string(rune('a'+i)) + ".txt"))
	}
	results := Classify(findings)
	for i, r := range results {
		if !r.IsCandidate {
			t.Fatalf("finding[%d]: expected PIIDB candidate from parent density", i)
		}
		if r.Scope != "parent" {
			t.Errorf("finding[%d]: Scope = %q, want parent", i, r.Scope)
		}
		if r.NewSeverity != detectors.SeverityHigh {
			t.Errorf("finding[%d]: Severity = %v, want High", i, r.NewSeverity)
		}
		if r.ParentCount != 5 {
			t.Errorf("finding[%d]: ParentCount = %d, want 5", i, r.ParentCount)
		}
	}
}

// TestClassify_SecretFindingsUnaffected verifies that non-PII findings
// pass through classification unchanged.
func TestClassify_SecretFindingsUnaffected(t *testing.T) {
	chunk := fsChunk("/app/secrets.env")
	findings := []engine.Finding{
		secretFinding(chunk),
		secretFinding(chunk),
		secretFinding(chunk),
		secretFinding(chunk),
	}
	results := Classify(findings)
	for i, r := range results {
		if r.IsCandidate {
			t.Errorf("finding[%d]: secret finding should not be classified as PIIDB candidate", i)
		}
	}
}

// TestClassify_MixedFindings verifies PII and secrets in same container
// only counts PII for density. With 2 PII in a .csv (structured,
// threshold=2), PIIDB should trigger for the PII findings but not secrets.
func TestClassify_MixedFindings(t *testing.T) {
	chunk := fsChunk("/data/mixed.csv")
	findings := []engine.Finding{
		piiFinding(chunk),
		secretFinding(chunk),
		piiFinding(chunk),
		secretFinding(chunk),
	}
	results := Classify(findings)
	if !results[0].IsCandidate {
		t.Error("2 PII findings in .csv (structured, threshold=2) should trigger PIIDB")
	}
	if results[1].IsCandidate {
		t.Error("secret finding should not be classified as PIIDB candidate")
	}
	if !results[2].IsCandidate {
		t.Error("second PII finding in .csv should also trigger")
	}
	if results[3].IsCandidate {
		t.Error("second secret finding should not be classified")
	}
}

// TestClassify_S3_ContainerDensity verifies the container model works
// for S3 objects.
func TestClassify_S3_ContainerDensity(t *testing.T) {
	chunk := s3Chunk("prod-data", "exports/customer_dump.csv")
	findings := make([]engine.Finding, 3)
	for i := range findings {
		findings[i] = piiFinding(chunk)
	}
	results := Classify(findings)
	for i, r := range results {
		if !r.IsCandidate {
			t.Fatalf("finding[%d]: S3 CSV with 3 PII should be PIIDB candidate", i)
		}
		if r.Format != "csv" {
			t.Errorf("finding[%d]: Format = %q, want csv", i, r.Format)
		}
	}
}

// TestClassify_Slack_ContainerDensity verifies Slack messages (no
// extension) can still trigger on container density.
func TestClassify_Slack_ContainerDensity(t *testing.T) {
	chunk := slackChunk("C12345", "1234567890.000100")
	findings := make([]engine.Finding, 3)
	for i := range findings {
		findings[i] = piiFinding(chunk)
	}
	results := Classify(findings)
	for i, r := range results {
		if !r.IsCandidate {
			t.Fatalf("finding[%d]: Slack with 3 PII in same message should trigger", i)
		}
		if r.Format != "" {
			t.Errorf("finding[%d]: Slack should have empty format, got %q", i, r.Format)
		}
		if r.NewSeverity != detectors.SeverityHigh {
			t.Errorf("finding[%d]: Severity = %v, want High", i, r.NewSeverity)
		}
	}
}

// TestClassify_Slack_ParentDensity verifies Slack channel-level parent
// grouping works.
func TestClassify_Slack_ParentDensity(t *testing.T) {
	findings := make([]engine.Finding, 5)
	for i := range findings {
		findings[i] = piiFinding(slackChunk("C12345", "ts_"+string(rune('0'+i))))
	}
	results := Classify(findings)
	for i, r := range results {
		if !r.IsCandidate {
			t.Fatalf("finding[%d]: 5 PII across same Slack channel should trigger parent density", i)
		}
		if r.Scope != "parent" {
			t.Errorf("finding[%d]: Scope = %q, want parent", i, r.Scope)
		}
	}
}

// TestClassify_NoParent_StillWorks verifies that sources without parent
// information degrade gracefully (container-only density still works).
func TestClassify_NoParent_StillWorks(t *testing.T) {
	chunk := &sources.Chunk{
		SourceName:     "custom-source",
		SourceMetadata: sources.Metadata{},
	}
	findings := make([]engine.Finding, 3)
	for i := range findings {
		findings[i] = piiFinding(chunk)
	}
	results := Classify(findings)
	for i, r := range results {
		if !r.IsCandidate {
			t.Fatalf("finding[%d]: 3 PII in same container (no parent) should trigger", i)
		}
		if r.Scope != "container" {
			t.Errorf("finding[%d]: Scope = %q, want container", i, r.Scope)
		}
		if r.ParentCount != 0 {
			t.Errorf("finding[%d]: ParentCount = %d, want 0 (no parent)", i, r.ParentCount)
		}
	}
}

// TestClassify_NeverDowngrades verifies that a finding already at
// Critical is not downgraded.
func TestClassify_NeverDowngrades(t *testing.T) {
	chunk := fsChunk("/data/dump.sql")
	findings := make([]engine.Finding, 3)
	for i := range findings {
		f := piiFinding(chunk)
		f.Result.Severity = detectors.SeverityCritical
		findings[i] = f
	}
	results := Classify(findings)
	for i, r := range results {
		if r.NewSeverity < detectors.SeverityCritical {
			t.Errorf("finding[%d]: severity should never downgrade, got %v", i, r.NewSeverity)
		}
	}
}

// TestApplyClassification verifies ExtraData is stamped correctly.
func TestApplyClassification(t *testing.T) {
	chunk := fsChunk("/data/users.csv")
	f := piiFinding(chunk)
	c := Classification{
		IsCandidate:  true,
		Scope:        "container",
		Count:        5,
		ParentCount:  8,
		Format:       "csv",
		Reason:       "container_density=5 threshold=2 format=csv",
		NewSeverity:  detectors.SeverityCritical,
		OrigSeverity: detectors.SeverityMedium,
	}
	ApplyClassification(&f, c)

	checks := map[string]string{
		"pii_db_candidate":    "true",
		"pii_db_scope":        "container",
		"pii_db_count":        "5",
		"pii_db_parent_count": "8",
		"pii_db_format":       "csv",
		"pii_db_reason":       "container_density=5 threshold=2 format=csv",
	}
	for k, want := range checks {
		got := f.Result.ExtraData[k]
		if got != want {
			t.Errorf("ExtraData[%q] = %q, want %q", k, got, want)
		}
	}
	if f.Result.Severity != detectors.SeverityCritical {
		t.Errorf("Severity = %v, want Critical", f.Result.Severity)
	}
}

// TestApplyClassification_NonCandidate verifies no-op for non-candidates.
func TestApplyClassification_NonCandidate(t *testing.T) {
	chunk := fsChunk("/app/config.yml")
	f := piiFinding(chunk)
	origExtra := len(f.Result.ExtraData)
	c := Classification{}
	ApplyClassification(&f, c)
	if len(f.Result.ExtraData) != origExtra {
		t.Error("non-candidate should not modify ExtraData")
	}
	if f.Result.Severity != detectors.SeverityMedium {
		t.Errorf("Severity should stay Medium, got %v", f.Result.Severity)
	}
}

// --- Threshold validation tests ---
// These tests document the threshold-selection rationale and verify the
// operating point against representative samples.

// TestThreshold_SingleEmail_InEnvFile represents the most common
// false-positive scenario: a single .env file with one admin email.
func TestThreshold_SingleEmail_InEnvFile(t *testing.T) {
	chunk := fsChunk("/app/.env")
	findings := []engine.Finding{piiFinding(chunk)}
	results := Classify(findings)
	if results[0].IsCandidate {
		t.Error("single PII in .env should NOT trigger (FP suppression)")
	}
}

// TestThreshold_TwoEmails_InCodeComment represents incidental mention
// of 2 people in a source file.
func TestThreshold_TwoEmails_InCodeComment(t *testing.T) {
	chunk := fsChunk("/app/src/main.go")
	findings := []engine.Finding{piiFinding(chunk), piiFinding(chunk)}
	results := Classify(findings)
	if results[0].IsCandidate {
		t.Error("2 PII in unstructured .go file should NOT trigger (FP suppression)")
	}
}

// TestThreshold_CustomerList_CSV represents a true-positive: customer
// data exported as CSV with 4 PII records.
func TestThreshold_CustomerList_CSV(t *testing.T) {
	chunk := fsChunk("/exports/customers.csv")
	findings := make([]engine.Finding, 4)
	for i := range findings {
		findings[i] = piiFinding(chunk)
	}
	results := Classify(findings)
	if !results[0].IsCandidate {
		t.Error("4 PII in .csv should trigger (true positive dataset)")
	}
}

// TestThreshold_DatabaseDump_SQL represents a true-positive: SQL dump.
func TestThreshold_DatabaseDump_SQL(t *testing.T) {
	chunk := fsChunk("/backups/prod_users.sql")
	findings := make([]engine.Finding, 6)
	for i := range findings {
		findings[i] = piiFinding(chunk)
	}
	results := Classify(findings)
	if !results[0].IsCandidate {
		t.Error("6 PII in .sql should trigger (true positive dataset)")
	}
	if results[0].NewSeverity != detectors.SeverityCritical {
		t.Errorf("6 PII in structured SQL should be Critical, got %v", results[0].NewSeverity)
	}
}

// TestThreshold_ScatteredTestFixtures represents a common false-positive
// scenario: test fixtures spread across a directory, each with 1 PII.
func TestThreshold_ScatteredTestFixtures(t *testing.T) {
	findings := make([]engine.Finding, 4)
	for i := range findings {
		findings[i] = piiFinding(fsChunk("/tests/fixtures/test_" + string(rune('a'+i)) + ".json"))
	}
	results := Classify(findings)
	for i, r := range results {
		if r.IsCandidate {
			t.Errorf("finding[%d]: 4 scattered single-PII test fixtures should NOT trigger "+
				"(each container has only 1 finding, parent has 4 < 5 threshold)", i)
		}
	}
}
