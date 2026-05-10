package storage

import (
	"strings"
	"testing"
)

func TestPlainText(t *testing.T) {
	got := ToText("Hello world")
	if got != "Hello world" {
		t.Errorf("ToText(%q) = %q, want %q", "Hello world", got, "Hello world")
	}
}

func TestParagraph(t *testing.T) {
	got := ToText("<p>Hello world</p>")
	if !strings.Contains(got, "Hello world") {
		t.Errorf("ToText(paragraph) = %q, want to contain 'Hello world'", got)
	}
}

func TestHeadings(t *testing.T) {
	for i := 1; i <= 6; i++ {
		input := strings.ReplaceAll("<h1>Title</h1>", "1", strings.Repeat("#", i)[0:1])
		input = strings.Replace(input, "1", "", 1)
		// Build proper heading tag.
		tag := "h" + strings.Repeat("", 0)
		_ = tag
	}
	// Direct test.
	tests := []struct {
		tag   string
		pfx   string
		input string
	}{
		{"h1", "# ", "<h1>Title</h1>"},
		{"h2", "## ", "<h2>Subtitle</h2>"},
		{"h3", "### ", "<h3>Section</h3>"},
		{"h4", "#### ", "<h4>Detail</h4>"},
		{"h5", "##### ", "<h5>Fine</h5>"},
		{"h6", "###### ", "<h6>Small</h6>"},
	}
	for _, tt := range tests {
		t.Run(tt.tag, func(t *testing.T) {
			got := ToText(tt.input)
			if !strings.Contains(got, tt.pfx) {
				t.Errorf("ToText(%q) = %q, want to contain %q", tt.input, got, tt.pfx)
			}
		})
	}
}

func TestBold(t *testing.T) {
	got := ToText("<strong>important</strong>")
	if !strings.Contains(got, "**important**") {
		t.Errorf("ToText(strong) = %q, want to contain **important**", got)
	}
}

func TestItalic(t *testing.T) {
	got := ToText("<em>emphasis</em>")
	if !strings.Contains(got, "*emphasis*") {
		t.Errorf("ToText(em) = %q, want to contain *emphasis*", got)
	}
}

func TestLink(t *testing.T) {
	got := ToText(`<a href="https://example.com">click here</a>`)
	if !strings.Contains(got, "click here") {
		t.Errorf("ToText(link) = %q, want to contain 'click here'", got)
	}
	if !strings.Contains(got, "(https://example.com)") {
		t.Errorf("ToText(link) = %q, want to contain '(https://example.com)'", got)
	}
}

func TestBreak(t *testing.T) {
	got := ToText("line1<br/>line2")
	if !strings.Contains(got, "line1\nline2") {
		t.Errorf("ToText(br) = %q, want line break between lines", got)
	}
}

func TestList(t *testing.T) {
	got := ToText("<ul><li>one</li><li>two</li></ul>")
	if !strings.Contains(got, "- one") {
		t.Errorf("ToText(ul) = %q, want to contain '- one'", got)
	}
	if !strings.Contains(got, "- two") {
		t.Errorf("ToText(ul) = %q, want to contain '- two'", got)
	}
}

func TestTable(t *testing.T) {
	got := ToText("<table><tr><td>A</td><td>B</td></tr></table>")
	if !strings.Contains(got, "A") || !strings.Contains(got, "B") {
		t.Errorf("ToText(table) = %q, want to contain A and B", got)
	}
	if !strings.Contains(got, "|") {
		t.Errorf("ToText(table) = %q, want to contain | delimiters", got)
	}
}

func TestCode(t *testing.T) {
	got := ToText("<code>fmt.Println</code>")
	if !strings.Contains(got, "`fmt.Println`") {
		t.Errorf("ToText(code) = %q, want backtick-wrapped code", got)
	}
}

func TestPreBlock(t *testing.T) {
	got := ToText("<pre>func main() {\n\treturn\n}</pre>")
	if !strings.Contains(got, "```") {
		t.Errorf("ToText(pre) = %q, want triple backtick fences", got)
	}
	if !strings.Contains(got, "func main()") {
		t.Errorf("ToText(pre) = %q, want to contain code content", got)
	}
}

func TestImage(t *testing.T) {
	got := ToText(`<img src="/download/attachments/123/img.png" alt="diagram"/>`)
	if !strings.Contains(got, "diagram") {
		t.Errorf("ToText(img) = %q, want to contain alt text", got)
	}
}

func TestStructuredMacro(t *testing.T) {
	input := `<ac:structured-macro ac:name="code"><ac:parameter ac:name="language">go</ac:parameter><ac:plain-text-body>fmt.Println("hello")</ac:plain-text-body></ac:structured-macro>`
	got := ToText(input)
	if !strings.Contains(got, "[code]") {
		t.Errorf("ToText(macro) = %q, want to contain [code]", got)
	}
	if !strings.Contains(got, "[/code]") {
		t.Errorf("ToText(macro) = %q, want to contain [/code]", got)
	}
	if !strings.Contains(got, "[language=go]") {
		t.Errorf("ToText(macro) = %q, want to contain [language=go]", got)
	}
	if !strings.Contains(got, `fmt.Println`) {
		t.Errorf("ToText(macro) = %q, want to contain code content", got)
	}
}

func TestRIUser(t *testing.T) {
	input := `<ri:user ri:userkey="abc123"/>`
	got := ToText(input)
	if !strings.Contains(got, "[user:abc123]") {
		t.Errorf("ToText(ri:user) = %q, want to contain [user:abc123]", got)
	}
}

func TestRIPage(t *testing.T) {
	input := `<ri:page ri:content-title="My Page"/>`
	got := ToText(input)
	if !strings.Contains(got, "[page:My Page]") {
		t.Errorf("ToText(ri:page) = %q, want to contain [page:My Page]", got)
	}
}

func TestRIAttachment(t *testing.T) {
	input := `<ri:attachment ri:filename="doc.pdf"/>`
	got := ToText(input)
	if !strings.Contains(got, "[attachment:doc.pdf]") {
		t.Errorf("ToText(ri:attachment) = %q, want to contain [attachment:doc.pdf]", got)
	}
}

func TestRIUrl(t *testing.T) {
	input := `<ri:url ri:value="https://example.com"/>`
	got := ToText(input)
	if !strings.Contains(got, "https://example.com") {
		t.Errorf("ToText(ri:url) = %q, want to contain URL", got)
	}
}

func TestUnknownACLElement(t *testing.T) {
	input := `<ac:custom-element ac:name="fancy">some content</ac:custom-element>`
	got := ToText(input)
	// Unknown ac: elements must NOT be silently dropped — raw XML fallback.
	if !strings.Contains(got, "raw:") {
		t.Errorf("ToText(unknown ac) = %q, want raw XML fallback (contains 'raw:')", got)
	}
}

func TestUnknownRIElement(t *testing.T) {
	input := `<ri:custom-resolver ri:id="x"/>`
	got := ToText(input)
	// Unknown ri: elements must NOT be silently dropped.
	if !strings.Contains(got, "ri:") {
		t.Errorf("ToText(unknown ri) = %q, want raw XML fallback (contains 'ri:')", got)
	}
}

func TestACLink(t *testing.T) {
	input := `<ac:link><ri:page ri:content-title="Home"/><ac:link-body>Go home</ac:link-body></ac:link>`
	got := ToText(input)
	if !strings.Contains(got, "Go home") {
		t.Errorf("ToText(ac:link) = %q, want to contain link body text", got)
	}
}

func TestCompoundFixture(t *testing.T) {
	// Realistic Confluence storage-format page with mixed elements.
	input := `<h1>API Keys</h1>
<p>This page documents our API keys.</p>
<ac:structured-macro ac:name="info">
<ac:rich-text-body>
<p><strong>Warning:</strong> Do not share these keys. Contact <ri:user ri:userkey="admin1"/> for access.</p>
</ac:rich-text-body>
</ac:structured-macro>
<table>
<tr><th>Service</th><th>Key</th></tr>
<tr><td>AWS</td><td>AKIAIOSFODNN7EXAMPLE</td></tr>
<tr><td>GitHub</td><td>ghp_ABCDEF1234567890</td></tr>
</table>
<ac:structured-macro ac:name="code">
<ac:parameter ac:name="language">bash</ac:parameter>
<ac:plain-text-body>export AWS_ACCESS_KEY_ID=AKIAIOSFODNN7EXAMPLE</ac:plain-text-body>
</ac:structured-macro>
<ul>
<li>Rotate keys every 90 days</li>
<li>Use <a href="https://vault.example.com">Vault</a> for secrets</li>
</ul>`

	got := ToText(input)

	checks := []string{
		"API Keys",
		"documents our API keys",
		"Warning:",
		"[user:admin1]",
		"AKIAIOSFODNN7EXAMPLE",
		"ghp_ABCDEF1234567890",
		"[code]",
		"[/code]",
		"[language=bash]",
		"Rotate keys every 90 days",
		"Vault",
		"https://vault.example.com",
		"Service",
		"AWS",
	}
	for _, want := range checks {
		if !strings.Contains(got, want) {
			t.Errorf("compound fixture: output missing %q\noutput:\n%s", want, got)
		}
	}
}

func TestEmptyInput(t *testing.T) {
	got := ToText("")
	if got != "" {
		t.Errorf("ToText(empty) = %q, want empty", got)
	}
}

func TestMalformedHTML(t *testing.T) {
	got := ToText("<p>unclosed paragraph with a secret key=ABC123")
	if !strings.Contains(got, "secret key=ABC123") {
		t.Errorf("ToText(malformed) = %q, want to contain text content", got)
	}
}
