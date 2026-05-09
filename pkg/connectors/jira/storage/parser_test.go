package storage

import (
	"strings"
	"testing"
)

func TestPlainText(t *testing.T) {
	input := `<p>hello world</p>`
	got, err := ToTextString(input)
	if err != nil {
		t.Fatalf("ToText: %v", err)
	}
	want := "hello world"
	if got != want {
		t.Errorf("got %q, want %q", got, want)
	}
}

func TestHeadings(t *testing.T) {
	input := `<h1>Title</h1><h2>Subtitle</h2>`
	got, err := ToTextString(input)
	if err != nil {
		t.Fatalf("ToText: %v", err)
	}
	if !strings.Contains(got, "Title") || !strings.Contains(got, "Subtitle") {
		t.Errorf("got %q, want headings", got)
	}
}

func TestList(t *testing.T) {
	input := `<ul><li>one</li><li>two</li></ul>`
	got, err := ToTextString(input)
	if err != nil {
		t.Fatalf("ToText: %v", err)
	}
	if !strings.Contains(got, "- one") || !strings.Contains(got, "- two") {
		t.Errorf("got %q, want bullet list", got)
	}
}

func TestOrderedList(t *testing.T) {
	input := `<ol><li>first</li><li>second</li></ol>`
	got, err := ToTextString(input)
	if err != nil {
		t.Fatalf("ToText: %v", err)
	}
	if !strings.Contains(got, "1. first") || !strings.Contains(got, "2. second") {
		t.Errorf("got %q, want ordered list", got)
	}
}

func TestCodeBlock(t *testing.T) {
	input := `<pre>fmt.Println("hi")</pre>`
	got, err := ToTextString(input)
	if err != nil {
		t.Fatalf("ToText: %v", err)
	}
	if !strings.Contains(got, "```") || !strings.Contains(got, "fmt.Println") {
		t.Errorf("got %q, want code block", got)
	}
}

func TestBlockquote(t *testing.T) {
	input := `<blockquote>quoted text</blockquote>`
	got, err := ToTextString(input)
	if err != nil {
		t.Fatalf("ToText: %v", err)
	}
	if !strings.Contains(got, "> quoted text") {
		t.Errorf("got %q, want blockquote", got)
	}
}

func TestTable(t *testing.T) {
	input := `<table><tr><th>H1</th><th>H2</th></tr><tr><td>A</td><td>B</td></tr></table>`
	got, err := ToTextString(input)
	if err != nil {
		t.Fatalf("ToText: %v", err)
	}
	for _, s := range []string{"H1", "H2", "A", "B"} {
		if !strings.Contains(got, s) {
			t.Errorf("got %q, want %q in table output", got, s)
		}
	}
}

func TestJiraCodeMacro(t *testing.T) {
	input := `<ac:structured-macro ac:name="code"><ac:plain-text-body>curl https://example.com</ac:plain-text-body></ac:structured-macro>`
	got, err := ToTextString(input)
	if err != nil {
		t.Fatalf("ToText: %v", err)
	}
	if !strings.Contains(got, "```") || !strings.Contains(got, "curl") {
		t.Errorf("got %q, want code macro", got)
	}
}

func TestJiraPanelMacro(t *testing.T) {
	input := `<ac:structured-macro ac:name="info"><p>some info</p></ac:structured-macro>`
	got, err := ToTextString(input)
	if err != nil {
		t.Fatalf("ToText: %v", err)
	}
	if !strings.Contains(got, "info") || !strings.Contains(got, "some info") {
		t.Errorf("got %q, want panel content", got)
	}
}

func TestInlineFormatting(t *testing.T) {
	input := `<p>This is <strong>bold</strong> and <em>italic</em> text.</p>`
	got, err := ToTextString(input)
	if err != nil {
		t.Fatalf("ToText: %v", err)
	}
	if !strings.Contains(got, "bold") || !strings.Contains(got, "italic") {
		t.Errorf("got %q, want inline formatting preserved as text", got)
	}
}

func TestBr(t *testing.T) {
	input := `<p>line1<br/>line2</p>`
	got, err := ToTextString(input)
	if err != nil {
		t.Fatalf("ToText: %v", err)
	}
	if !strings.Contains(got, "line1\nline2") {
		t.Errorf("got %q, want line break", got)
	}
}

func TestHr(t *testing.T) {
	input := `<hr/>`
	got, err := ToTextString(input)
	if err != nil {
		t.Fatalf("ToText: %v", err)
	}
	if !strings.Contains(got, "---") {
		t.Errorf("got %q, want ---", got)
	}
}

func TestImg(t *testing.T) {
	input := `<img alt="diagram.png" src="http://example.com/d.png"/>`
	got, err := ToTextString(input)
	if err != nil {
		t.Fatalf("ToText: %v", err)
	}
	if !strings.Contains(got, "diagram.png") {
		t.Errorf("got %q, want alt text", got)
	}
}

func TestSkipsHead(t *testing.T) {
	input := `<html><head><title>ignore</title></head><body><p>content</p></body></html>`
	got, err := ToTextString(input)
	if err != nil {
		t.Fatalf("ToText: %v", err)
	}
	if strings.Contains(got, "ignore") {
		t.Errorf("got %q, should not contain head/title content", got)
	}
	if !strings.Contains(got, "content") {
		t.Errorf("got %q, want body content", got)
	}
}

func TestUnknownMacroPassThrough(t *testing.T) {
	input := `<ac:structured-macro ac:name="custom-macro"><p>inner content</p></ac:structured-macro>`
	got, err := ToTextString(input)
	if err != nil {
		t.Fatalf("ToText: %v", err)
	}
	if !strings.Contains(got, "inner content") {
		t.Errorf("got %q, want pass-through of unknown macro content", got)
	}
}
