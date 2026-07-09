package main

import "testing"

func TestScoreFiles(t *testing.T) {
	groundTruth := []string{"aws.txt", "azure.txt", "slack.txt"}
	knownMiss := map[string]string{"azure.txt": "regex bug, see spec.go"}
	findingsByTool := map[string][]finding{
		"pleno-dlp":  {{Tool: "pleno-dlp", File: "/corpus/aws.txt"}, {Tool: "pleno-dlp", File: "/corpus/slack.txt"}},
		"trufflehog": {{Tool: "trufflehog", File: "/corpus/aws.txt"}},
		"gitleaks":   {},
	}

	rows, recalls := scoreFiles(groundTruth, knownMiss, findingsByTool)

	if len(rows) != 3 {
		t.Fatalf("expected 3 rows, got %d", len(rows))
	}
	// rows are sorted by file name: aws.txt, azure.txt, slack.txt
	if rows[0].File != "aws.txt" || !rows[0].Detected["pleno-dlp"] || !rows[0].Detected["trufflehog"] || rows[0].Detected["gitleaks"] {
		t.Errorf("aws.txt row wrong: %+v", rows[0])
	}
	if rows[1].File != "azure.txt" || rows[1].KnownMiss == "" {
		t.Errorf("azure.txt row should carry its known-miss note: %+v", rows[1])
	}
	if rows[1].Detected["pleno-dlp"] {
		t.Errorf("azure.txt should not be detected by pleno-dlp in this fixture")
	}

	byTool := map[string]recall{}
	for _, r := range recalls {
		byTool[r.Tool] = r
	}
	if got := byTool["pleno-dlp"]; got.Hit != 2 || got.Total != 3 {
		t.Errorf("pleno-dlp recall = %+v, want Hit=2 Total=3", got)
	}
	if got := byTool["gitleaks"]; got.Hit != 0 || len(got.Misses) != 3 {
		t.Errorf("gitleaks recall = %+v, want Hit=0 and all 3 missed", got)
	}
	// The whole point of issue #298: pleno-dlp's own miss must show up,
	// not just be summarized away as "2/3".
	found := false
	for _, m := range byTool["pleno-dlp"].Misses {
		if m == "azure.txt" {
			found = true
		}
	}
	if !found {
		t.Errorf("pleno-dlp's miss list must include azure.txt (its own loss), got %v", byTool["pleno-dlp"].Misses)
	}
}
