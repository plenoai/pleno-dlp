// Package storage converts Confluence storage-format XHTML to plain text.
//
// Confluence stores page and comment bodies as XHTML with Confluence-specific
// namespace elements (`ac:*` for macros/links/parameters, `ri:*` for resource
// identifiers like users, pages, and attachments). This parser walks the HTML
// token stream, emitting text that preserves semantic structure while stripping
// markup noise.
//
// Known Confluence elements:
//   - ac:structured-macro → [macro:name] ... [/macro]
//   - ac:link             → link text or URL
//   - ac:parameter        → [param:name=value]
//   - ac:plain-text-body  → raw text content
//   - ac:rich-text-body   → recurse into children
//   - ri:user             → [user:key]
//   - ri:page             → [page:title]
//   - ri:attachment       → [attachment:name]
//
// Standard XHTML elements (p, h1-h6, li, td, pre, a, etc.) are handled with
// appropriate spacing. Unknown ac:/ri: elements fall back to raw XML so no
// content is silently dropped.
package storage

import (
	"bytes"
	"fmt"
	"strings"

	"golang.org/x/net/html"
)

// ToText converts Confluence storage-format XHTML into readable plain text.
// Returns the text with semantic structure preserved and markup stripped.
func ToText(xhtml string) string {
	doc, err := html.Parse(strings.NewReader(xhtml))
	if err != nil {
		// If the XHTML is malformed, return it as-is so detectors can still
		// scan the raw content.
		return xhtml
	}
	var buf strings.Builder
	walk(doc, &buf)
	return strings.TrimSpace(buf.String())
}

// walk recursively walks the HTML node tree, writing text to buf.
func walk(n *html.Node, buf *strings.Builder) {
	if n == nil {
		return
	}

	switch n.Type {
	case html.TextNode:
		text := strings.TrimSpace(n.Data)
		if text != "" {
			ensureSpace(buf)
			buf.WriteString(text)
		}
		return
	case html.CommentNode, html.DoctypeNode:
		return
	}

	prefix, suffix, block := elementFormat(n)

	if block && buf.Len() > 0 && !endsWithNewline(buf) {
		buf.WriteByte('\n')
	}
	if prefix != "" {
		buf.WriteString(prefix)
	}

	for c := n.FirstChild; c != nil; c = c.NextSibling {
		walk(c, buf)
	}

	if suffix != "" {
		buf.WriteString(suffix)
	}
	if block && buf.Len() > 0 && !endsWithNewline(buf) {
		buf.WriteByte('\n')
	}
}

// elementFormat returns (prefix, suffix, isBlock) for a given HTML element.
func elementFormat(n *html.Node) (prefix, suffix string, block bool) {
	tag := n.Data

	switch tag {
	case "p", "div", "section", "article", "main", "header", "footer",
		"nav", "aside", "blockquote", "figcaption":
		return "", "\n", true
	case "h1":
		return "# ", "\n", true
	case "h2":
		return "## ", "\n", true
	case "h3":
		return "### ", "\n", true
	case "h4":
		return "#### ", "\n", true
	case "h5":
		return "##### ", "\n", true
	case "h6":
		return "###### ", "\n", true
	case "br":
		return "\n", "", false
	case "hr":
		return "---\n", "", true
	case "ul", "ol":
		return "", "\n", true
	case "li":
		return "- ", "\n", false
	case "table":
		return "", "\n", true
	case "tr":
		return "| ", " |\n", false
	case "td", "th":
		return "", " | ", false
	case "thead", "tbody", "tfoot":
		return "", "", false
	case "pre":
		return "```\n", "\n```\n", true
	case "code":
		if n.Parent == nil || n.Parent.Data != "pre" {
			return "`", "`", false
		}
		return "", "", false
	case "strong", "b":
		return "**", "**", false
	case "em", "i":
		return "*", "*", false
	case "del", "s":
		return "~~", "~~", false
	case "a":
		href := attrVal(n, "href")
		if href != "" {
			return "", fmt.Sprintf(" (%s)", href), false
		}
		return "", "", false
	case "img":
		src := attrVal(n, "src")
		alt := attrVal(n, "alt")
		if alt != "" && src != "" {
			return fmt.Sprintf("![%s](", alt), ")", false
		}
		if src != "" {
			return fmt.Sprintf("![image](%s)", src), "", false
		}
		return "", "", false
	case "span", "font", "center":
		return "", "", false
	case "sup":
		return "^", "^", false
	case "sub":
		return "~", "~", false
	}

	if strings.HasPrefix(tag, "ac:") {
		return confluenceElementFormat(n)
	}
	if strings.HasPrefix(tag, "ri:") {
		return riElementFormat(n)
	}

	return "", "", false
}

func confluenceElementFormat(n *html.Node) (prefix, suffix string, block bool) {
	tag := n.Data
	switch tag {
	case "ac:structured-macro":
		name := attrVal(n, "ac:name")
		if name == "" {
			name = "macro"
		}
		return fmt.Sprintf("[%s]", name), fmt.Sprintf("[/%s]", name), true
	case "ac:parameter":
		name := attrVal(n, "ac:name")
		value := textContent(n)
		if name != "" && value != "" {
			return fmt.Sprintf("[%s=%s]", name, value), "", false
		}
		if value != "" {
			return value, "", false
		}
		return "", "", false
	case "ac:plain-text-body":
		value := textContent(n)
		if value != "" {
			return value, "", true
		}
		return "", "", false
	case "ac:rich-text-body":
		return "", "", false
	case "ac:link":
		return "", "", false
	case "ac:plain-text-link-body":
		return textContent(n), "", false
	case "ac:link-body":
		return "", "", false
	default:
		// Unknown ac: element — emit raw XML so nothing is silently dropped.
		raw := renderNode(n)
		return fmt.Sprintf("[raw:%s]", raw), "", false
	}
}

func riElementFormat(n *html.Node) (prefix, suffix string, block bool) {
	tag := n.Data
	switch tag {
	case "ri:user":
		key := attrVal(n, "ri:userkey")
		if key == "" {
			key = attrVal(n, "ri:username")
		}
		if key == "" {
			key = "unknown"
		}
		return fmt.Sprintf("[user:%s]", key), "", false
	case "ri:page":
		title := attrVal(n, "ri:content-title")
		if title == "" {
			title = attrVal(n, "ri:page-title")
		}
		if title == "" {
			title = "untitled"
		}
		return fmt.Sprintf("[page:%s]", title), "", false
	case "ri:attachment":
		name := attrVal(n, "ri:filename")
		if name == "" {
			name = "unknown"
		}
		return fmt.Sprintf("[attachment:%s]", name), "", false
	case "ri:url":
		val := attrVal(n, "ri:value")
		if val != "" {
			return val, "", false
		}
		return "", "", false
	default:
		raw := renderNode(n)
		return fmt.Sprintf("[ri:%s]", raw), "", false
	}
}

func attrVal(n *html.Node, key string) string {
	for _, a := range n.Attr {
		if a.Key == key {
			return a.Val
		}
	}
	return ""
}

func textContent(n *html.Node) string {
	var buf strings.Builder
	for c := n.FirstChild; c != nil; c = c.NextSibling {
		if c.Type == html.TextNode {
			buf.WriteString(c.Data)
		} else if c.Type == html.ElementNode {
			buf.WriteString(textContent(c))
		}
	}
	return strings.TrimSpace(buf.String())
}

func renderNode(n *html.Node) string {
	var buf bytes.Buffer
	buf.WriteString("<" + n.Data)
	for _, a := range n.Attr {
		buf.WriteString(fmt.Sprintf(" %s=%q", a.Key, a.Val))
	}
	if n.FirstChild == nil {
		buf.WriteString("/>")
		return buf.String()
	}
	buf.WriteString(">")
	inner := textContent(n)
	if len(inner) > 200 {
		inner = inner[:200] + "..."
	}
	buf.WriteString(inner)
	buf.WriteString("</" + n.Data + ">")
	return buf.String()
}

func endsWithNewline(buf *strings.Builder) bool {
	if buf.Len() == 0 {
		return true
	}
	return buf.String()[buf.Len()-1] == '\n'
}

func ensureSpace(buf *strings.Builder) {
	if buf.Len() == 0 {
		return
	}
	last := buf.String()[buf.Len()-1]
	// `*`, `~`, and backtick mean we just emitted a markup prefix
	// (`**` for strong, `*` for em, `~~` for del, `` ` `` for code) —
	// pasting a space between marker and content would corrupt the
	// rendered markdown ("** important**" vs "**important**").
	if last != ' ' && last != '\n' && last != '[' && last != '(' && last != '|' &&
		last != '*' && last != '~' && last != '`' {
		buf.WriteByte(' ')
	}
}
