package adf

import (
	"testing"
)

func TestText(t *testing.T) {
	input := `{"type":"doc","content":[{"type":"paragraph","content":[{"type":"text","text":"hello world"}]}]}`
	got, err := ToText([]byte(input))
	if err != nil {
		t.Fatalf("ToText: %v", err)
	}
	want := "hello world"
	if got != want {
		t.Errorf("got %q, want %q", got, want)
	}
}

func TestHeading(t *testing.T) {
	input := `{"type":"doc","content":[{"type":"heading","attrs":{"level":2},"content":[{"type":"text","text":"Title"}]}]}`
	got, err := ToText([]byte(input))
	if err != nil {
		t.Fatalf("ToText: %v", err)
	}
	want := "## Title"
	if got != want {
		t.Errorf("got %q, want %q", got, want)
	}
}

func TestBulletList(t *testing.T) {
	input := `{"type":"doc","content":[{"type":"bulletList","content":[{"type":"listItem","content":[{"type":"paragraph","content":[{"type":"text","text":"one"}]}]},{"type":"listItem","content":[{"type":"paragraph","content":[{"type":"text","text":"two"}]}]}]}]}`
	got, err := ToText([]byte(input))
	if err != nil {
		t.Fatalf("ToText: %v", err)
	}
	if !contains(got, "- one") || !contains(got, "- two") {
		t.Errorf("got %q, want bullet list items", got)
	}
}

func TestOrderedList(t *testing.T) {
	input := `{"type":"doc","content":[{"type":"orderedList","attrs":{"order":1},"content":[{"type":"listItem","content":[{"type":"paragraph","content":[{"type":"text","text":"first"}]}]},{"type":"listItem","content":[{"type":"paragraph","content":[{"type":"text","text":"second"}]}]}]}]}`
	got, err := ToText([]byte(input))
	if err != nil {
		t.Fatalf("ToText: %v", err)
	}
	if !contains(got, "1. first") || !contains(got, "2. second") {
		t.Errorf("got %q, want ordered list items", got)
	}
}

func TestCodeBlock(t *testing.T) {
	input := `{"type":"doc","content":[{"type":"codeBlock","attrs":{"language":"go"},"content":[{"type":"text","text":"fmt.Println(\"hi\")"}]}]}`
	got, err := ToText([]byte(input))
	if err != nil {
		t.Fatalf("ToText: %v", err)
	}
	if !contains(got, "```go") || !contains(got, "fmt.Println") {
		t.Errorf("got %q, want code block with language", got)
	}
}

func TestBlockquote(t *testing.T) {
	input := `{"type":"doc","content":[{"type":"blockquote","content":[{"type":"paragraph","content":[{"type":"text","text":"quoted text"}]}]}]}`
	got, err := ToText([]byte(input))
	if err != nil {
		t.Fatalf("ToText: %v", err)
	}
	if !contains(got, "> quoted text") {
		t.Errorf("got %q, want blockquote", got)
	}
}

func TestTable(t *testing.T) {
	input := `{"type":"doc","content":[{"type":"table","content":[{"type":"tableRow","content":[{"type":"tableHeader","content":[{"type":"paragraph","content":[{"type":"text","text":"H1"}]}]},{"type":"tableHeader","content":[{"type":"paragraph","content":[{"type":"text","text":"H2"}]}]}]},{"type":"tableRow","content":[{"type":"tableCell","content":[{"type":"paragraph","content":[{"type":"text","text":"A"}]}]},{"type":"tableCell","content":[{"type":"paragraph","content":[{"type":"text","text":"B"}]}]}]}]}]}`
	got, err := ToText([]byte(input))
	if err != nil {
		t.Fatalf("ToText: %v", err)
	}
	if !contains(got, "H1") || !contains(got, "H2") || !contains(got, "A") || !contains(got, "B") {
		t.Errorf("got %q, want table content", got)
	}
}

func TestMention(t *testing.T) {
	input := `{"type":"doc","content":[{"type":"paragraph","content":[{"type":"mention","attrs":{"id":"abc123","text":"@alice"}}]}]}`
	got, err := ToText([]byte(input))
	if err != nil {
		t.Fatalf("ToText: %v", err)
	}
	if !contains(got, "@alice") {
		t.Errorf("got %q, want @alice", got)
	}
}

func TestEmoji(t *testing.T) {
	input := `{"type":"doc","content":[{"type":"paragraph","content":[{"type":"emoji","attrs":{"shortName":":smile:"}}]}]}`
	got, err := ToText([]byte(input))
	if err != nil {
		t.Fatalf("ToText: %v", err)
	}
	if !contains(got, ":smile:") {
		t.Errorf("got %q, want :smile:", got)
	}
}

func TestStatus(t *testing.T) {
	input := `{"type":"doc","content":[{"type":"paragraph","content":[{"type":"status","attrs":{"text":"In Progress","color":"blue"}}]}]}`
	got, err := ToText([]byte(input))
	if err != nil {
		t.Fatalf("ToText: %v", err)
	}
	if !contains(got, "In Progress") {
		t.Errorf("got %q, want status text", got)
	}
}

func TestRule(t *testing.T) {
	input := `{"type":"doc","content":[{"type":"rule"}]}`
	got, err := ToText([]byte(input))
	if err != nil {
		t.Fatalf("ToText: %v", err)
	}
	if !contains(got, "---") {
		t.Errorf("got %q, want ---", got)
	}
}

func TestHardBreak(t *testing.T) {
	input := `{"type":"doc","content":[{"type":"paragraph","content":[{"type":"text","text":"line1"},{"type":"hardBreak"},{"type":"text","text":"line2"}]}]}`
	got, err := ToText([]byte(input))
	if err != nil {
		t.Fatalf("ToText: %v", err)
	}
	if !contains(got, "line1\nline2") {
		t.Errorf("got %q, want line break between lines", got)
	}
}

func TestInlineCard(t *testing.T) {
	input := `{"type":"doc","content":[{"type":"paragraph","content":[{"type":"inlineCard","attrs":{"url":"https://example.com"}}]}]}`
	got, err := ToText([]byte(input))
	if err != nil {
		t.Fatalf("ToText: %v", err)
	}
	if !contains(got, "https://example.com") {
		t.Errorf("got %q, want URL", got)
	}
}

func TestMedia(t *testing.T) {
	input := `{"type":"doc","content":[{"type":"mediaSingle","content":[{"type":"media","attrs":{"alt":"screenshot.png"}}]}]}`
	got, err := ToText([]byte(input))
	if err != nil {
		t.Fatalf("ToText: %v", err)
	}
	if !contains(got, "screenshot.png") {
		t.Errorf("got %q, want media alt text", got)
	}
}

func TestDate(t *testing.T) {
	input := `{"type":"doc","content":[{"type":"paragraph","content":[{"type":"date","attrs":{"timestamp":"2024-01-15"}}]}]}`
	got, err := ToText([]byte(input))
	if err != nil {
		t.Fatalf("ToText: %v", err)
	}
	if !contains(got, "2024-01-15") {
		t.Errorf("got %q, want date timestamp", got)
	}
}

func TestPanel(t *testing.T) {
	input := `{"type":"doc","content":[{"type":"panel","attrs":{"panelType":"warning"},"content":[{"type":"paragraph","content":[{"type":"text","text":"heads up"}]}]}]}`
	got, err := ToText([]byte(input))
	if err != nil {
		t.Fatalf("ToText: %v", err)
	}
	if !contains(got, "warning") || !contains(got, "heads up") {
		t.Errorf("got %q, want panel type and content", got)
	}
}

func TestUnknownNode(t *testing.T) {
	input := `{"type":"doc","content":[{"type":"customWidget","attrs":{"foo":"bar"},"content":[{"type":"text","text":"inner"}]}]}`
	got, err := ToText([]byte(input))
	if err != nil {
		t.Fatalf("ToText: %v", err)
	}
	// Unknown nodes must NOT be silently dropped; raw JSON is emitted.
	if !contains(got, "customWidget") {
		t.Errorf("got %q, want raw JSON for unknown node", got)
	}
}

func TestCompoundDocument(t *testing.T) {
	// A more realistic ADF document with multiple node types.
	input := `{
		"type": "doc",
		"content": [
			{"type": "heading", "attrs": {"level": 1}, "content": [{"type": "text", "text": "Bug Report"}]},
			{"type": "paragraph", "content": [{"type": "text", "text": "The system crashes when"}]},
			{"type": "codeBlock", "attrs": {"language": "bash"}, "content": [{"type": "text", "text": "curl https://example.com"}]},
			{"type": "paragraph", "content": [
				{"type": "text", "text": "Reported by "},
				{"type": "mention", "attrs": {"id": "u1", "text": "@bob"}},
				{"type": "text", "text": "."}
			]},
			{"type": "rule"},
			{"type": "paragraph", "content": [{"type": "text", "text": "End."}]}
		]
	}`
	got, err := ToText([]byte(input))
	if err != nil {
		t.Fatalf("ToText: %v", err)
	}
	for _, substr := range []string{"# Bug Report", "crashes when", "```bash", "curl", "@bob", "---", "End."} {
		if !contains(got, substr) {
			t.Errorf("compound doc missing %q in: %q", substr, got)
		}
	}
}

func TestInvalidJSON(t *testing.T) {
	_, err := ToText([]byte(`not json`))
	if err == nil {
		t.Fatal("expected error for invalid JSON")
	}
}

func contains(s, sub string) bool {
	return len(s) >= len(sub) && (s == sub || len(sub) == 0 || stringContains(s, sub))
}

func stringContains(s, sub string) bool {
	for i := 0; i+len(sub) <= len(s); i++ {
		if s[i:i+len(sub)] == sub {
			return true
		}
	}
	return false
}
