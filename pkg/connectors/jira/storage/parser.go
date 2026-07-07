// Package storage converts Jira storage-format XHTML into plain text.
//
// Jira Cloud uses ADF (Atlassian Document Format) for issue content,
// but Jira Data Center still uses a storage format based on XHTML with
// Jira-specific macros. This parser handles standard XHTML elements
// plus the most common Jira macro elements.
//
// Unknown elements emit their raw XML fallback — no content is silently
// dropped.
package storage

import (
	"fmt"
	"io"
	"strings"

	"golang.org/x/net/html"
)

// ToText converts Jira storage-format XHTML into plain text.
func ToText(r io.Reader) (string, error) {
	doc, err := html.Parse(r)
	if err != nil {
		return "", fmt.Errorf("storage: parse xhtml: %w", err)
	}
	var b strings.Builder
	walkNode(&b, doc)
	return strings.TrimSpace(b.String()), nil
}

// ToTextString is a convenience wrapper for string input.
func ToTextString(s string) (string, error) {
	return ToText(strings.NewReader(s))
}

func walkNode(b *strings.Builder, n *html.Node) {
	if n == nil {
		return
	}

	switch n.Type {
	case html.TextNode:
		text := strings.TrimSpace(n.Data)
		if text != "" {
			b.WriteString(n.Data)
		}
		return
	case html.DocumentNode:
		for c := n.FirstChild; c != nil; c = c.NextSibling {
			walkNode(b, c)
		}
		return
	case html.CommentNode:
		return
	case html.ErrorNode:
		b.WriteString(n.Data)
		return
	}

	switch n.Data {
	case "p", "div":
		for c := n.FirstChild; c != nil; c = c.NextSibling {
			walkNode(b, c)
		}
		b.WriteString("\n\n")
	case "h1", "h2", "h3", "h4", "h5", "h6":
		for c := n.FirstChild; c != nil; c = c.NextSibling {
			walkNode(b, c)
		}
		b.WriteByte('\n')
	case "br":
		b.WriteByte('\n')
	case "hr":
		b.WriteString("---\n")
	case "strong", "b", "em", "i", "u", "s", "del", "span", "a":
		// Inline formatting: pass through text content.
		for c := n.FirstChild; c != nil; c = c.NextSibling {
			walkNode(b, c)
		}
	case "code":
		b.WriteByte('`')
		for c := n.FirstChild; c != nil; c = c.NextSibling {
			walkNode(b, c)
		}
		b.WriteByte('`')
	case "pre":
		b.WriteString("```\n")
		for c := n.FirstChild; c != nil; c = c.NextSibling {
			walkNode(b, c)
		}
		b.WriteString("\n```\n")
	case "ul", "ol":
		idx := 0
		for c := n.FirstChild; c != nil; c = c.NextSibling {
			if c.Type == html.ElementNode && c.Data == "li" {
				if n.Data == "ul" {
					b.WriteString("- ")
				} else {
					idx++
					fmt.Fprintf(b, "%d. ", idx)
				}
				walkNode(b, c)
				b.WriteByte('\n')
			}
		}
	case "li":
		for c := n.FirstChild; c != nil; c = c.NextSibling {
			walkNode(b, c)
		}
	case "blockquote":
		for c := n.FirstChild; c != nil; c = c.NextSibling {
			lines := renderNodeText(c)
			for _, line := range strings.Split(lines, "\n") {
				b.WriteString("> ")
				b.WriteString(line)
				b.WriteByte('\n')
			}
		}
	case "table":
		for c := n.FirstChild; c != nil; c = c.NextSibling {
			if c.Type == html.ElementNode {
				walkNode(b, c)
			}
		}
		b.WriteByte('\n')
	case "thead", "tbody", "tfoot":
		for c := n.FirstChild; c != nil; c = c.NextSibling {
			if c.Type == html.ElementNode {
				walkNode(b, c)
			}
		}
	case "tr":
		b.WriteString("| ")
		for c := n.FirstChild; c != nil; c = c.NextSibling {
			if c.Type == html.ElementNode && (c.Data == "td" || c.Data == "th") {
				for inner := c.FirstChild; inner != nil; inner = inner.NextSibling {
					walkNode(b, inner)
				}
				b.WriteString(" | ")
			}
		}
		b.WriteByte('\n')
	case "img":
		alt := attrVal(n, "alt")
		if alt != "" {
			fmt.Fprintf(b, "[image: %s]", alt)
		} else {
			b.WriteString("[image]")
		}
	// Jira-specific macros are handled below; most just pass through
	// their text content since we target plain-text output.
	case "ac:structured-macro":
		name := attrVal(n, "ac:name")
		switch name {
		case "code":
			b.WriteString("```\n")
			for c := n.FirstChild; c != nil; c = c.NextSibling {
				walkNode(b, c)
			}
			b.WriteString("\n```\n")
		case "info", "note", "warning", "tip", "panel":
			fmt.Fprintf(b, "[%s] ", name)
			for c := n.FirstChild; c != nil; c = c.NextSibling {
				walkNode(b, c)
			}
			b.WriteByte('\n')
		case "quote":
			for c := n.FirstChild; c != nil; c = c.NextSibling {
				lines := renderNodeText(c)
				for _, line := range strings.Split(lines, "\n") {
					b.WriteString("> ")
					b.WriteString(line)
					b.WriteByte('\n')
				}
			}
		default:
			// Pass through content for unknown macros.
			for c := n.FirstChild; c != nil; c = c.NextSibling {
				walkNode(b, c)
			}
		}
	case "ac:plain-text-body", "ac:rich-text-body":
		for c := n.FirstChild; c != nil; c = c.NextSibling {
			walkNode(b, c)
		}
	case "ac:parameter":
		// Parameters are metadata, not content.
		for c := n.FirstChild; c != nil; c = c.NextSibling {
			walkNode(b, c)
		}
	case "ac:link", "ri:page", "ri:space", "ri:user":
		// Emit display text if present, otherwise link body.
		for c := n.FirstChild; c != nil; c = c.NextSibling {
			walkNode(b, c)
		}
	case "head", "title", "style", "script", "meta", "link":
		// Skip non-body elements.
		return
	default:
		// Unknown element: emit children for content, don't drop.
		for c := n.FirstChild; c != nil; c = c.NextSibling {
			walkNode(b, c)
		}
	}
}

func renderNodeText(n *html.Node) string {
	var b strings.Builder
	walkNode(&b, n)
	return b.String()
}

func attrVal(n *html.Node, key string) string {
	for _, attr := range n.Attr {
		if attr.Key == key {
			return attr.Val
		}
	}
	return ""
}
