package markdown

import (
	"encoding/json"
	"strings"
	"testing"
)

func blockJSON(blockType string, fields map[string]any) json.RawMessage {
	obj := map[string]any{"type": blockType, "id": "test-id"}
	for k, v := range fields {
		obj[k] = v
	}
	raw, _ := json.Marshal(obj)
	return raw
}

func richTextItem(text string, annotations map[string]bool) map[string]any {
	ann := map[string]any{
		"bold": false, "italic": false, "strikethrough": false,
		"underline": false, "code": false, "color": "default",
	}
	for k, v := range annotations {
		ann[k] = v
	}
	return map[string]any{
		"type":        "text",
		"plain_text":  text,
		"annotations": ann,
	}
}

func TestParagraph(t *testing.T) {
	blocks := []json.RawMessage{
		blockJSON("paragraph", map[string]any{
			"rich_text": []any{richTextItem("hello world", nil)},
		}),
	}
	got := ConvertBlocks(blocks)
	if !strings.Contains(got, "hello world") {
		t.Errorf("got %q, want to contain 'hello world'", got)
	}
}

func TestHeading123(t *testing.T) {
	cases := []struct {
		level  int
		prefix string
	}{
		{1, "# "},
		{2, "## "},
		{3, "### "},
	}
	for _, c := range cases {
		t.Run(string(rune('0'+c.level)), func(t *testing.T) {
			typ := "heading_" + string(rune('0'+c.level))
			blocks := []json.RawMessage{
				blockJSON(typ, map[string]any{
					"rich_text": []any{richTextItem("Title", nil)},
				}),
			}
			got := ConvertBlocks(blocks)
			if !strings.HasPrefix(got, c.prefix) {
				t.Errorf("got %q, want prefix %q", got, c.prefix)
			}
			if !strings.Contains(got, "Title") {
				t.Errorf("got %q, want to contain 'Title'", got)
			}
		})
	}
}

func TestBulletedListItem(t *testing.T) {
	blocks := []json.RawMessage{
		blockJSON("bulleted_list_item", map[string]any{
			"rich_text": []any{richTextItem("item one", nil)},
		}),
	}
	got := ConvertBlocks(blocks)
	if !strings.Contains(got, "- item one") {
		t.Errorf("got %q, want to contain '- item one'", got)
	}
}

func TestNumberedListItem(t *testing.T) {
	blocks := []json.RawMessage{
		blockJSON("numbered_list_item", map[string]any{
			"rich_text": []any{richTextItem("step one", nil)},
		}),
	}
	got := ConvertBlocks(blocks)
	if !strings.Contains(got, "1. step one") {
		t.Errorf("got %q, want to contain '1. step one'", got)
	}
}

func TestToDo_CheckedAndUnchecked(t *testing.T) {
	cases := []struct {
		name    string
		checked bool
		want    string
	}{
		{"unchecked", false, "[ ]"},
		{"checked", true, "[x]"},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			blocks := []json.RawMessage{
				blockJSON("to_do", map[string]any{
					"rich_text": []any{richTextItem("task", nil)},
					"checked":   c.checked,
				}),
			}
			got := ConvertBlocks(blocks)
			if !strings.Contains(got, c.want) {
				t.Errorf("got %q, want to contain %q", got, c.want)
			}
		})
	}
}

func TestToggle(t *testing.T) {
	blocks := []json.RawMessage{
		blockJSON("toggle", map[string]any{
			"rich_text": []any{richTextItem("click me", nil)},
		}),
	}
	got := ConvertBlocks(blocks)
	if !strings.Contains(got, "click me (toggle)") {
		t.Errorf("got %q, want to contain 'click me (toggle)'", got)
	}
}

func TestCode(t *testing.T) {
	blocks := []json.RawMessage{
		blockJSON("code", map[string]any{
			"rich_text": []any{richTextItem("fmt.Println(\"hello\")", nil)},
			"language":  "go",
		}),
	}
	got := ConvertBlocks(blocks)
	if !strings.Contains(got, "```go") {
		t.Errorf("got %q, want to contain '```go'", got)
	}
	if !strings.Contains(got, "fmt.Println") {
		t.Errorf("got %q, want to contain 'fmt.Println'", got)
	}
}

func TestQuote(t *testing.T) {
	blocks := []json.RawMessage{
		blockJSON("quote", map[string]any{
			"rich_text": []any{richTextItem("wise words", nil)},
		}),
	}
	got := ConvertBlocks(blocks)
	if !strings.Contains(got, "> wise words") {
		t.Errorf("got %q, want to contain '> wise words'", got)
	}
}

func TestCallout(t *testing.T) {
	blocks := []json.RawMessage{
		blockJSON("callout", map[string]any{
			"rich_text": []any{richTextItem("note", nil)},
			"icon": map[string]any{
				"type":  "emoji",
				"emoji": "💡",
			},
		}),
	}
	got := ConvertBlocks(blocks)
	if !strings.Contains(got, "💡 note") {
		t.Errorf("got %q, want to contain '💡 note'", got)
	}
}

func TestDivider(t *testing.T) {
	blocks := []json.RawMessage{
		blockJSON("divider", map[string]any{}),
	}
	got := ConvertBlocks(blocks)
	if !strings.Contains(got, "---") {
		t.Errorf("got %q, want to contain '---'", got)
	}
}

func TestEquation(t *testing.T) {
	blocks := []json.RawMessage{
		blockJSON("equation", map[string]any{
			"expression": "E = mc^2",
		}),
	}
	got := ConvertBlocks(blocks)
	if !strings.Contains(got, "$$E = mc^2$$") {
		t.Errorf("got %q, want to contain '$$E = mc^2$$'", got)
	}
}

// TestImage uses the real Notion API structure where image content is
// nested under the "image" key.
func TestImage(t *testing.T) {
	blocks := []json.RawMessage{
		func() json.RawMessage {
			obj := map[string]any{
				"type": "image",
				"id":   "test-id",
				"image": map[string]any{
					"type":     "external",
					"external": map[string]any{"url": "https://example.com/img.png"},
					"caption":  []any{richTextItem("diagram", nil)},
				},
			}
			raw, _ := json.Marshal(obj)
			return raw
		}(),
	}
	got := ConvertBlocks(blocks)
	if !strings.Contains(got, "![diagram](https://example.com/img.png)") {
		t.Errorf("got %q, want image markdown", got)
	}
}

// TestFile uses the real Notion API structure where file content is
// nested under the "file" key.
func TestFile(t *testing.T) {
	blocks := []json.RawMessage{
		func() json.RawMessage {
			obj := map[string]any{
				"type": "file",
				"id":   "test-id",
				"file": map[string]any{
					"type":     "external",
					"external": map[string]any{"url": "https://example.com/doc.pdf"},
					"caption":  []any{richTextItem("report", nil)},
				},
			}
			raw, _ := json.Marshal(obj)
			return raw
		}(),
	}
	got := ConvertBlocks(blocks)
	if !strings.Contains(got, "[report](https://example.com/doc.pdf)") {
		t.Errorf("got %q, want file link", got)
	}
}

func TestEmbed(t *testing.T) {
	blocks := []json.RawMessage{
		blockJSON("embed", map[string]any{
			"url": "https://example.com/embed",
		}),
	}
	got := ConvertBlocks(blocks)
	if !strings.Contains(got, "[embed](https://example.com/embed)") {
		t.Errorf("got %q, want embed link", got)
	}
}

func TestChildPage(t *testing.T) {
	blocks := []json.RawMessage{
		blockJSON("child_page", map[string]any{
			"title": "Sub Page",
		}),
	}
	got := ConvertBlocks(blocks)
	if !strings.Contains(got, "## Sub Page") {
		t.Errorf("got %q, want '## Sub Page'", got)
	}
}

func TestChildDatabase(t *testing.T) {
	blocks := []json.RawMessage{
		blockJSON("child_database", map[string]any{
			"title": "My DB",
		}),
	}
	got := ConvertBlocks(blocks)
	if !strings.Contains(got, "## Database: My DB") {
		t.Errorf("got %q, want '## Database: My DB'", got)
	}
}

func TestTable(t *testing.T) {
	rows := []json.RawMessage{
		json.RawMessage(`{"type":"table_row","cells":[[{"type":"text","plain_text":"Name","annotations":{"bold":false,"italic":false,"strikethrough":false,"underline":false,"code":false,"color":"default"}}],[{"type":"text","plain_text":"Age","annotations":{"bold":false,"italic":false,"strikethrough":false,"underline":false,"code":false,"color":"default"}}]]}`),
		json.RawMessage(`{"type":"table_row","cells":[[{"type":"text","plain_text":"Alice","annotations":{"bold":false,"italic":false,"strikethrough":false,"underline":false,"code":false,"color":"default"}}],[{"type":"text","plain_text":"30","annotations":{"bold":false,"italic":false,"strikethrough":false,"underline":false,"code":false,"color":"default"}}]]}`),
	}
	rowsJSON, _ := json.Marshal(rows)
	blocks := []json.RawMessage{
		func() json.RawMessage {
			obj := map[string]any{
				"type":        "table",
				"id":          "tbl1",
				"table_width": 2,
				"children":    json.RawMessage(rowsJSON),
			}
			raw, _ := json.Marshal(obj)
			return raw
		}(),
	}
	got := ConvertBlocks(blocks)
	if !strings.Contains(got, "Name") || !strings.Contains(got, "Age") {
		t.Errorf("got %q, want table headers", got)
	}
	if !strings.Contains(got, "Alice") || !strings.Contains(got, "30") {
		t.Errorf("got %q, want table data", got)
	}
	if !strings.Contains(got, "---") {
		t.Errorf("got %q, want table separator", got)
	}
}

func TestUnknownBlock_RendersAsFencedCode(t *testing.T) {
	blocks := []json.RawMessage{
		blockJSON("unsupported_block_type", map[string]any{
			"data": "some value",
		}),
	}
	got := ConvertBlocks(blocks)
	if !strings.Contains(got, "```") {
		t.Errorf("got %q, want fenced code block for unknown type", got)
	}
	if !strings.Contains(got, "unsupported_block_type") {
		t.Errorf("got %q, want to contain the block type in raw JSON", got)
	}
}

func TestRichTextAnnotations(t *testing.T) {
	cases := []struct {
		name        string
		annotations map[string]bool
		wantSubstr  string
	}{
		{"bold", map[string]bool{"bold": true}, "**hello**"},
		{"italic", map[string]bool{"italic": true}, "*hello*"},
		{"strikethrough", map[string]bool{"strikethrough": true}, "~~hello~~"},
		{"code", map[string]bool{"code": true}, "`hello`"},
		{"underline", map[string]bool{"underline": true}, "<u>hello</u>"},
		{"bold+italic", map[string]bool{"bold": true, "italic": true}, "***hello***"},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			blocks := []json.RawMessage{
				blockJSON("paragraph", map[string]any{
					"rich_text": []any{richTextItem("hello", c.annotations)},
				}),
			}
			got := ConvertBlocks(blocks)
			if !strings.Contains(got, c.wantSubstr) {
				t.Errorf("got %q, want to contain %q", got, c.wantSubstr)
			}
		})
	}
}

func TestRichTextLink(t *testing.T) {
	rt := richTextItem("docs", nil)
	rt["href"] = "https://example.com"
	blocks := []json.RawMessage{
		blockJSON("paragraph", map[string]any{
			"rich_text": []any{rt},
		}),
	}
	got := ConvertBlocks(blocks)
	if !strings.Contains(got, "[docs](https://example.com)") {
		t.Errorf("got %q, want markdown link", got)
	}
}

func TestCompoundFixture(t *testing.T) {
	var blocks []json.RawMessage
	blocks = append(blocks, blockJSON("heading_1", map[string]any{
		"rich_text": []any{richTextItem("Project Status", nil)},
	}))
	blocks = append(blocks, blockJSON("paragraph", map[string]any{
		"rich_text": []any{
			richTextItem("The ", nil),
			richTextItem("build", map[string]bool{"bold": true}),
			richTextItem(" is ", nil),
			richTextItem("passing", map[string]bool{"italic": true}),
		},
	}))
	blocks = append(blocks, blockJSON("divider", map[string]any{}))
	blocks = append(blocks, blockJSON("bulleted_list_item", map[string]any{
		"rich_text": []any{richTextItem("Tests green", nil)},
	}))
	blocks = append(blocks, blockJSON("code", map[string]any{
		"rich_text": []any{richTextItem("make test", nil)},
		"language":  "bash",
	}))

	got := ConvertBlocks(blocks)

	checks := []string{
		"# Project Status",
		"**build**",
		"*passing*",
		"---",
		"- Tests green",
		"```bash",
		"make test",
	}
	for _, want := range checks {
		if !strings.Contains(got, want) {
			t.Errorf("compound fixture: got %q, want to contain %q", got, want)
		}
	}
}

func TestNestedChildren(t *testing.T) {
	childBlock := blockJSON("paragraph", map[string]any{
		"rich_text": []any{richTextItem("nested content", nil)},
	})
	children, _ := json.Marshal([]json.RawMessage{childBlock})
	blocks := []json.RawMessage{
		func() json.RawMessage {
			obj := map[string]any{
				"type":      "paragraph",
				"id":        "parent",
				"rich_text": []any{richTextItem("parent content", nil)},
				"children":  json.RawMessage(children),
			}
			raw, _ := json.Marshal(obj)
			return raw
		}(),
	}
	got := ConvertBlocks(blocks)
	if !strings.Contains(got, "parent content") {
		t.Errorf("got %q, want parent content", got)
	}
	if !strings.Contains(got, "nested content") {
		t.Errorf("got %q, want nested content", got)
	}
}

func TestEmptyBlocks(t *testing.T) {
	got := ConvertBlocks(nil)
	if got != "" {
		t.Errorf("got %q, want empty string for nil blocks", got)
	}
	got = ConvertBlocks([]json.RawMessage{})
	if got != "" {
		t.Errorf("got %q, want empty string for empty blocks", got)
	}
}

func TestMalformedJSON(t *testing.T) {
	blocks := []json.RawMessage{json.RawMessage(`not json at all`)}
	got := ConvertBlocks(blocks)
	if !strings.Contains(got, "```") {
		t.Errorf("got %q, want fenced code block for malformed JSON", got)
	}
}
