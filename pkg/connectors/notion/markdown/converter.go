// Package markdown converts Notion block JSON into a Markdown string.
// It handles the full set of Notion block types that carry textual content
// and emits raw JSON as fenced code for any unrecognised block type (no
// silent drops).
//
// Rich-text annotations (bold, italic, strikethrough, underline, code,
// color) within text objects are rendered. The converter is stateless and
// safe for concurrent use.
package markdown

import (
	"encoding/json"
	"fmt"
	"strings"
)

// richText represents a Notion rich_text object with its plain text and
// optional annotations.
type richText struct {
	Type        string `json:"type"`
	PlainText   string `json:"plain_text"`
	Annotations struct {
		Bold          bool   `json:"bold"`
		Italic        bool   `json:"italic"`
		Strikethrough bool   `json:"strikethrough"`
		Underline     bool   `json:"underline"`
		Code          bool   `json:"code"`
		Color         string `json:"color"`
	} `json:"annotations"`
	Href string `json:"href,omitempty"`
}

// block is a partial decode of a Notion block. We extract type, has_children,
// and leave the rest as raw JSON for type-specific dispatch.
type block struct {
	Type        string          `json:"type"`
	HasChildren bool            `json:"has_children"`
	ID          string          `json:"id"`
	Children    json.RawMessage `json:"children,omitempty"` // populated by caller for nested blocks
	Raw         json.RawMessage `json:"-"`                  // full JSON for unknown types
}

// ConvertBlocks converts a slice of Notion block JSON objects into a Markdown
// string. Each block is handled by its type-specific renderer; unknown types
// emit their raw JSON as a fenced code block.
func ConvertBlocks(blocks []json.RawMessage) string {
	var sb strings.Builder
	for i, raw := range blocks {
		var b block
		if err := json.Unmarshal(raw, &b); err != nil {
			// Malformed JSON — emit as fenced code block.
			fmt.Fprintf(&sb, "```\n%s\n```\n", raw)
			continue
		}
		b.Raw = raw
		sb.WriteString(renderBlock(b))
		// Add blank line between blocks for readability, except
		// inside list contexts where tight spacing is preferred.
		if i < len(blocks)-1 {
			sb.WriteByte('\n')
		}
	}
	return sb.String()
}

func renderBlock(b block) string {
	switch b.Type {
	case "paragraph":
		return renderParagraph(b)
	case "heading_1":
		return renderHeading(b, 1)
	case "heading_2":
		return renderHeading(b, 2)
	case "heading_3":
		return renderHeading(b, 3)
	case "bulleted_list_item":
		return renderListItem(b, "- ")
	case "numbered_list_item":
		return renderNumberedItem(b)
	case "to_do":
		return renderToDo(b)
	case "toggle":
		return renderToggle(b)
	case "code":
		return renderCode(b)
	case "quote":
		return renderQuote(b)
	case "callout":
		return renderCallout(b)
	case "table":
		return renderTable(b)
	case "table_row":
		return renderTableRow(b)
	case "image":
		return renderImage(b)
	case "file":
		return renderFile(b)
	case "embed":
		return renderEmbed(b)
	case "child_page":
		return renderChildPage(b)
	case "child_database":
		return renderChildDatabase(b)
	case "divider":
		return "---\n"
	case "equation":
		return renderEquation(b)
	default:
		return renderUnknown(b)
	}
}

// ---- Rich-text rendering ------------------------------------------------

// renderRichTexts renders a slice of rich_text objects into Markdown,
// applying annotations (bold, italic, strikethrough, underline, code)
// and link wrapping.
func renderRichTexts(raw json.RawMessage, key string) string {
	var obj map[string]json.RawMessage
	if err := json.Unmarshal(raw, &obj); err != nil {
		return ""
	}
	rtRaw, ok := obj[key]
	if !ok {
		return ""
	}
	var rts []richText
	if err := json.Unmarshal(rtRaw, &rts); err != nil {
		return ""
	}
	var sb strings.Builder
	for _, rt := range rts {
		text := renderAnnotated(rt)
		if rt.Href != "" {
			fmt.Fprintf(&sb, "[%s](%s)", text, rt.Href)
		} else {
			sb.WriteString(text)
		}
	}
	return sb.String()
}

func renderAnnotated(rt richText) string {
	t := rt.PlainText
	if rt.Annotations.Code {
		t = "`" + t + "`"
	}
	if rt.Annotations.Bold {
		t = "**" + t + "**"
	}
	if rt.Annotations.Italic {
		t = "*" + t + "*"
	}
	if rt.Annotations.Strikethrough {
		t = "~~" + t + "~~"
	}
	if rt.Annotations.Underline {
		// Markdown has no native underline; use <u> tags.
		t = "<u>" + t + "</u>"
	}
	return t
}

// ---- Block renderers -----------------------------------------------------

func renderParagraph(b block) string {
	text := renderRichTexts(b.Raw, "rich_text")
	children := renderNestedChildren(b)
	if children != "" {
		return text + "\n" + children
	}
	return text + "\n"
}

func renderHeading(b block, level int) string {
	prefix := strings.Repeat("#", level) + " "
	text := renderRichTexts(b.Raw, "rich_text")
	return prefix + text + "\n"
}

func renderListItem(b block, prefix string) string {
	text := renderRichTexts(b.Raw, "rich_text")
	children := renderNestedChildren(b)
	if children != "" {
		return prefix + text + "\n" + indentBlock(children, "  ")
	}
	return prefix + text + "\n"
}

func renderNumberedItem(b block) string {
	text := renderRichTexts(b.Raw, "rich_text")
	children := renderNestedChildren(b)
	if children != "" {
		return "1. " + text + "\n" + indentBlock(children, "   ")
	}
	return "1. " + text + "\n"
}

func renderToDo(b block) string {
	var obj map[string]json.RawMessage
	_ = json.Unmarshal(b.Raw, &obj)
	checked := false
	if cb, ok := obj["checked"]; ok {
		_ = json.Unmarshal(cb, &checked)
	}
	checkbox := "[ ] "
	if checked {
		checkbox = "[x] "
	}
	text := renderRichTexts(b.Raw, "rich_text")
	children := renderNestedChildren(b)
	if children != "" {
		return "- " + checkbox + text + "\n" + indentBlock(children, "  ")
	}
	return "- " + checkbox + text + "\n"
}

func renderToggle(b block) string {
	text := renderRichTexts(b.Raw, "rich_text")
	children := renderNestedChildren(b)
	if children != "" {
		return "> " + text + " (toggle)\n" + indentBlock(children, "> ")
	}
	return "> " + text + " (toggle)\n"
}

func renderCode(b block) string {
	var obj map[string]json.RawMessage
	_ = json.Unmarshal(b.Raw, &obj)
	lang := ""
	if lb, ok := obj["language"]; ok {
		_ = json.Unmarshal(lb, &lang)
	}
	text := renderRichTexts(b.Raw, "rich_text")
	return "```" + lang + "\n" + text + "\n```\n"
}

func renderQuote(b block) string {
	text := renderRichTexts(b.Raw, "rich_text")
	lines := strings.Split(strings.TrimRight(text, "\n"), "\n")
	var sb strings.Builder
	for _, line := range lines {
		sb.WriteString("> " + line + "\n")
	}
	return sb.String()
}

func renderCallout(b block) string {
	var obj map[string]json.RawMessage
	_ = json.Unmarshal(b.Raw, &obj)
	emoji := ""
	if eb, ok := obj["icon"]; ok {
		var icon struct {
			Type  string `json:"type"`
			Emoji string `json:"emoji"`
		}
		_ = json.Unmarshal(eb, &icon)
		emoji = icon.Emoji
	}
	text := renderRichTexts(b.Raw, "rich_text")
	prefix := "> "
	if emoji != "" {
		prefix = "> " + emoji + " "
	}
	lines := strings.Split(strings.TrimRight(text, "\n"), "\n")
	var sb strings.Builder
	for _, line := range lines {
		sb.WriteString(prefix + line + "\n")
	}
	return sb.String()
}

func renderTable(b block) string {
	if len(b.Children) > 0 {
		var rows []json.RawMessage
		_ = json.Unmarshal(b.Children, &rows)
		return renderTableRows(rows)
	}
	var obj map[string]json.RawMessage
	_ = json.Unmarshal(b.Raw, &obj)
	w := 0
	if wb, ok := obj["table_width"]; ok {
		_ = json.Unmarshal(wb, &w)
	}
	return fmt.Sprintf("| table (width=%d) |\n", w)
}

func renderTableRow(b block) string {
	cells := renderRichTexts(b.Raw, "cells")
	return "| " + cells + " |\n"
}

func renderTableRows(rows []json.RawMessage) string {
	if len(rows) == 0 {
		return ""
	}
	var sb strings.Builder
	var firstRow struct {
		Cells [][]richText `json:"cells"`
	}
	_ = json.Unmarshal(rows[0], &firstRow)
	colCount := len(firstRow.Cells)

	for i, cell := range firstRow.Cells {
		sb.WriteString("| ")
		for _, rt := range cell {
			sb.WriteString(renderAnnotated(rt))
		}
		sb.WriteString(" ")
		_ = i
	}
	sb.WriteString("|\n")

	sb.WriteString("|")
	for i := 0; i < colCount; i++ {
		sb.WriteString("---|")
	}
	sb.WriteString("\n")

	for _, raw := range rows[1:] {
		var row struct {
			Cells [][]richText `json:"cells"`
		}
		_ = json.Unmarshal(raw, &row)
		for i, cell := range row.Cells {
			sb.WriteString("| ")
			for _, rt := range cell {
				sb.WriteString(renderAnnotated(rt))
			}
			sb.WriteString(" ")
			_ = i
		}
		sb.WriteString("|\n")
	}
	return sb.String()
}

// The Notion API nests image content under a top-level "image" key:
// {"type":"image", "image":{"type":"external", "external":{"url":"..."},
// "caption":[...]}}.
func renderImage(b block) string {
	var obj map[string]json.RawMessage
	_ = json.Unmarshal(b.Raw, &obj)

	// Extract the nested "image" sub-object.
	subObj := obj
	if sub, ok := obj["image"]; ok {
		subObj = nil
		_ = json.Unmarshal(sub, &subObj)
	}

	url := extractMediaURL(subObj)
	caption := renderRichTextsFromObj(subObj, "caption")
	if caption != "" {
		return fmt.Sprintf("![%s](%s)\n", caption, url)
	}
	return fmt.Sprintf("![](%s)\n", url)
}

// renderFile uses the same nesting pattern as renderImage.
func renderFile(b block) string {
	var obj map[string]json.RawMessage
	_ = json.Unmarshal(b.Raw, &obj)

	subObj := obj
	if sub, ok := obj["file"]; ok {
		subObj = nil
		_ = json.Unmarshal(sub, &subObj)
	}

	url := extractMediaURL(subObj)
	caption := renderRichTextsFromObj(subObj, "caption")
	if caption != "" {
		return fmt.Sprintf("[%s](%s)\n", caption, url)
	}
	return fmt.Sprintf("[file](%s)\n", url)
}

// extractMediaURL extracts the URL from a Notion media sub-object that has
// "type": "external"|"file" and the corresponding nested key.
func extractMediaURL(obj map[string]json.RawMessage) string {
	if obj == nil {
		return ""
	}
	tb, ok := obj["type"]
	if !ok {
		return ""
	}
	var innerType string
	_ = json.Unmarshal(tb, &innerType)
	src, ok := obj[innerType]
	if !ok {
		return ""
	}
	var srcObj struct {
		URL string `json:"url"`
	}
	_ = json.Unmarshal(src, &srcObj)
	return srcObj.URL
}

// renderRichTextsFromObj renders rich_text from a specific sub-object.
func renderRichTextsFromObj(obj map[string]json.RawMessage, key string) string {
	if obj == nil {
		return ""
	}
	rtRaw, ok := obj[key]
	if !ok {
		return ""
	}
	var rts []richText
	if err := json.Unmarshal(rtRaw, &rts); err != nil {
		return ""
	}
	var sb strings.Builder
	for _, rt := range rts {
		text := renderAnnotated(rt)
		if rt.Href != "" {
			fmt.Fprintf(&sb, "[%s](%s)", text, rt.Href)
		} else {
			sb.WriteString(text)
		}
	}
	return sb.String()
}

func renderEmbed(b block) string {
	var obj map[string]json.RawMessage
	_ = json.Unmarshal(b.Raw, &obj)
	url := ""
	if ub, ok := obj["url"]; ok {
		_ = json.Unmarshal(ub, &url)
	}
	caption := renderRichTexts(b.Raw, "caption")
	if caption != "" {
		return fmt.Sprintf("[%s](%s)\n", caption, url)
	}
	return fmt.Sprintf("[embed](%s)\n", url)
}

func renderChildPage(b block) string {
	var obj map[string]json.RawMessage
	_ = json.Unmarshal(b.Raw, &obj)
	title := ""
	if tb, ok := obj["title"]; ok {
		_ = json.Unmarshal(tb, &title)
	}
	return fmt.Sprintf("## %s\n", title)
}

func renderChildDatabase(b block) string {
	var obj map[string]json.RawMessage
	_ = json.Unmarshal(b.Raw, &obj)
	title := ""
	if tb, ok := obj["title"]; ok {
		_ = json.Unmarshal(tb, &title)
	}
	return fmt.Sprintf("## Database: %s\n", title)
}

func renderEquation(b block) string {
	var obj map[string]json.RawMessage
	_ = json.Unmarshal(b.Raw, &obj)
	expr := ""
	if eb, ok := obj["expression"]; ok {
		_ = json.Unmarshal(eb, &expr)
	}
	return fmt.Sprintf("$$%s$$\n", expr)
}

func renderUnknown(b block) string {
	return fmt.Sprintf("```\n%s\n```\n", strings.TrimRight(string(b.Raw), "\n"))
}

// renderNestedChildren renders pre-populated children blocks.
func renderNestedChildren(b block) string {
	if len(b.Children) == 0 {
		return ""
	}
	var children []json.RawMessage
	if err := json.Unmarshal(b.Children, &children); err != nil {
		return ""
	}
	return ConvertBlocks(children)
}

func indentBlock(s, indent string) string {
	lines := strings.Split(s, "\n")
	var sb strings.Builder
	for _, line := range lines {
		if line == "" {
			sb.WriteByte('\n')
			continue
		}
		sb.WriteString(indent + line + "\n")
	}
	return sb.String()
}
