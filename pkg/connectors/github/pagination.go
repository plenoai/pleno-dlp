package github

import "strings"

// parseLinkHeader returns the URL of the rel="next" link from a GitHub
// Link response header, or "" if there is no next page.
//
// GitHub paginates list endpoints (orgs/<org>/repos, search, ...) by
// stuffing absolute URLs for first / prev / next / last into a single
// Link header:
//
//	Link: <https://api.github.com/orgs/foo/repos?page=2>; rel="next",
//	      <https://api.github.com/orgs/foo/repos?page=5>; rel="last"
//
// Cursor advance is therefore the URL the server hands us — not a
// "page=N+1" guess — so we follow the rel="next" href verbatim.
//
// Implementation note: we do a small hand-rolled parse rather than
// pulling in net/textproto or a third-party Link parser. The format is
// regular enough that strings.Split is fine, and we consciously avoid
// adding a dependency for one header.
func parseLinkHeader(header string) string {
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
