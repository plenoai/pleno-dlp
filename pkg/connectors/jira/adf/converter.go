// Package adf converts Atlassian Document Format (ADF) JSON trees into
// plain text. ADF is the native content representation for Jira Cloud
// issue descriptions and comments.
//
// Every node type listed in the Atlassian ADF spec (doc, paragraph,
// heading, bulletList, orderedList, listItem, codeBlock, blockquote,
// panel, table, tableRow, tableCell, tableHeader, mediaSingle,
// mediaGroup, media, mention, emoji, status, date, inlineCard,
// blockCard, rule, hardBreak, text) has an explicit handler. Unknown
// nodes emit their raw JSON so no content is silently dropped.
//
// Marks (strong, em, code, link, strikethrough, underline, subsup,
// textColor, backgroundColor) are recognised but not rendered — the
// output is plain text, not rich text.
package adf

import (
	"encoding/json"
	"fmt"
	"strconv"
	"strings"
)

type node struct {
	Type    string          `json:"type"`
	Content []node          `json:"content,omitempty"`
	Text    string          `json:"text,omitempty"`
	Attrs   json.RawMessage `json:"attrs,omitempty"`
	Marks   []mark          `json:"marks,omitempty"`
}

type mark struct {
	Type  string          `json:"type"`
	Attrs json.RawMessage `json:"attrs,omitempty"`
}

// ToText converts an ADF JSON document into plain text. The input must
// be a valid ADF JSON tree (root type "doc"). Unknown node types are
// emitted as their raw JSON representation so no content is silently
// dropped.
func ToText(data []byte) (string, error) {
	var doc node
	if err := json.Unmarshal(data, &doc); err != nil {
		return "", fmt.Errorf("adf: invalid json: %w", err)
	}
	var b strings.Builder
	renderNode(&b, &doc, 0)
	return strings.TrimSpace(b.String()), nil
}

// renderNode dispatches on node.Type and appends its text representation
// to b. depth is the current nesting depth for indentation.
func renderNode(b *strings.Builder, n *node, depth int) {
	switch n.Type {
	case "doc":
		renderChildren(b, n, depth)
	case "paragraph":
		renderChildren(b, n, depth)
		b.WriteString("\n\n")
	case "heading":
		level := attrInt(n.Attrs, "level", 1)
		fmt.Fprintf(b, "%s ", strings.Repeat("#", level))
		renderChildren(b, n, depth)
		b.WriteString("\n\n")
	case "bulletList":
		for i, child := range n.Content {
			b.WriteString(strings.Repeat("  ", depth))
			b.WriteString("- ")
			renderNode(b, &child, depth+1)
			if i < len(n.Content)-1 {
				b.WriteByte('\n')
			}
		}
		b.WriteString("\n")
	case "orderedList":
		order := attrInt(n.Attrs, "order", 1)
		for i, child := range n.Content {
			b.WriteString(strings.Repeat("  ", depth))
			fmt.Fprintf(b, "%d. ", order+i)
			renderNode(b, &child, depth+1)
			if i < len(n.Content)-1 {
				b.WriteByte('\n')
			}
		}
		b.WriteString("\n")
	case "listItem":
		renderChildren(b, n, depth)
	case "codeBlock":
		lang := attrString(n.Attrs, "language", "")
		if lang != "" {
			fmt.Fprintf(b, "```%s\n", lang)
		} else {
			b.WriteString("```\n")
		}
		// codeBlock content is typically a single text node, but
		// handle children generically.
		renderChildrenInline(b, n)
		b.WriteString("\n```\n")
	case "blockquote":
		for _, child := range n.Content {
			lines := strings.Split(renderNodeString(&child, depth), "\n")
			for _, line := range lines {
				b.WriteString("> ")
				b.WriteString(line)
				b.WriteByte('\n')
			}
		}
	case "panel":
		panelType := attrString(n.Attrs, "panelType", "info")
		fmt.Fprintf(b, "[%s] ", panelType)
		renderChildren(b, n, depth)
		b.WriteByte('\n')
	case "table":
		// Render table rows; each row on a new line.
		for _, row := range n.Content {
			if row.Type == "tableRow" {
				renderTableRow(b, &row)
			}
		}
		b.WriteByte('\n')
	case "tableRow":
		renderTableRow(b, n)
	case "tableCell", "tableHeader":
		renderChildrenInline(b, n)
		b.WriteString(" | ")
	case "mediaSingle":
		renderChildrenInline(b, n)
		b.WriteByte('\n')
	case "mediaGroup":
		renderChildrenInline(b, n)
		b.WriteByte('\n')
	case "media":
		alt := attrString(n.Attrs, "alt", "")
		if alt != "" {
			fmt.Fprintf(b, "[media: %s]", alt)
		} else {
			b.WriteString("[media]")
		}
	case "mention":
		text := attrString(n.Attrs, "text", "")
		if text != "" {
			b.WriteString(text)
		} else {
			id := attrString(n.Attrs, "id", "")
			fmt.Fprintf(b, "@%s", id)
		}
	case "emoji":
		shortName := attrString(n.Attrs, "shortName", "")
		if shortName != "" {
			b.WriteString(shortName)
		} else {
			b.WriteString(":emoji:")
		}
	case "status":
		text := attrString(n.Attrs, "text", "")
		color := attrString(n.Attrs, "color", "")
		if text != "" {
			fmt.Fprintf(b, "[%s", text)
			if color != "" {
				fmt.Fprintf(b, " (%s)", color)
			}
			b.WriteByte(']')
		}
	case "date":
		timestamp := attrString(n.Attrs, "timestamp", "")
		if timestamp != "" {
			b.WriteString(timestamp)
		}
	case "inlineCard":
		url := attrString(n.Attrs, "url", "")
		if url != "" {
			b.WriteString(url)
		} else {
			// data is sometimes a nested JSON object with url.
			b.WriteString("[inline card]")
		}
	case "blockCard":
		url := attrString(n.Attrs, "url", "")
		if url != "" {
			b.WriteString(url)
		} else {
			b.WriteString("[block card]")
		}
	case "rule":
		b.WriteString("---\n")
	case "hardBreak":
		b.WriteByte('\n')
	case "text":
		b.WriteString(n.Text)
	default:
		// Unknown node: emit raw JSON so no content is silently dropped.
		raw, err := json.Marshal(n)
		if err != nil {
			raw = []byte(fmt.Sprintf("{unknown: %s}", n.Type))
		}
		b.Write(raw)
	}
}

func renderChildren(b *strings.Builder, n *node, depth int) {
	for _, child := range n.Content {
		renderNode(b, &child, depth)
	}
}

// renderChildrenInline renders children without appending block-level
// separators. Used inside code blocks and table cells.
func renderChildrenInline(b *strings.Builder, n *node) {
	for _, child := range n.Content {
		// text nodes are the main inline content.
		if child.Type == "text" {
			b.WriteString(child.Text)
		} else {
			renderNode(b, &child, 0)
		}
	}
}

func renderTableRow(b *strings.Builder, n *node) {
	b.WriteString("| ")
	for _, cell := range n.Content {
		renderNode(b, &cell, 0)
	}
	b.WriteByte('\n')
}

// renderNodeString renders a node and returns the resulting string.
func renderNodeString(n *node, depth int) string {
	var b strings.Builder
	renderNode(&b, n, depth)
	return b.String()
}

// attrString extracts a string attribute from the raw attrs JSON. Returns
// def if the key is missing or not a string.
func attrString(raw json.RawMessage, key, def string) string {
	if len(raw) == 0 {
		return def
	}
	var m map[string]any
	if err := json.Unmarshal(raw, &m); err != nil {
		return def
	}
	v, ok := m[key]
	if !ok {
		return def
	}
	s, ok := v.(string)
	if !ok {
		return def
	}
	return s
}

// attrInt extracts an int attribute from the raw attrs JSON. Returns def
// if the key is missing or not a number.
func attrInt(raw json.RawMessage, key string, def int) int {
	if len(raw) == 0 {
		return def
	}
	var m map[string]any
	if err := json.Unmarshal(raw, &m); err != nil {
		return def
	}
	v, ok := m[key]
	if !ok {
		return def
	}
	// JSON numbers unmarshal as float64.
	switch n := v.(type) {
	case float64:
		return int(n)
	case string:
		if i, err := strconv.Atoi(n); err == nil {
			return i
		}
	}
	return def
}
