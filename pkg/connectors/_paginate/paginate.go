// Package _paginate provides shared pagination helpers for SaaS connectors.
// Extracted from the GitHub connector so GitLab (and future providers) can
// reuse Link-header parsing without importing each other's packages.
package _paginate

import "strings"

// ParseLinkHeader returns the URL of the rel="next" link from an HTTP Link
// response header, or "" if there is no next page.
//
// Both GitHub and GitLab paginate list endpoints by stuffing absolute URLs
// for first / prev / next / last into a single Link header:
//
//	Link: <https://api.example.com/items?page=2>; rel="next",
//	      <https://api.example.com/items?page=5>; rel="last"
//
// Cursor advance is the URL the server hands us — not a "page=N+1" guess —
// so we follow the rel="next" href verbatim.
//
// Implementation note: hand-rolled parse rather than pulling in a dependency.
// The format is regular enough that strings.Split is fine.
func ParseLinkHeader(header string) string {
	if header == "" {
		return ""
	}
	for _, segment := range strings.Split(header, ",") {
		s := strings.TrimSpace(segment)
		if !strings.HasPrefix(s, "<") {
			continue
		}
		end := strings.Index(s, ">")
		if end < 0 {
			continue
		}
		u := s[1:end]
		for _, p := range strings.Split(s[end+1:], ";") {
			kv := strings.TrimSpace(p)
			// rel can be quoted or unquoted (servers emit both). We
			// match both forms strictly so a stray rel="next-page"
			// doesn't trip the wrong cursor.
			if kv == `rel="next"` || kv == `rel=next` {
				return u
			}
		}
	}
	return ""
}
