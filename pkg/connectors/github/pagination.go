package github

import "github.com/plenoai/pleno-dlp/pkg/connectors/_paginate"

// parseLinkHeader delegates to the shared Link-header parser in
// _paginate. Kept as a local wrapper so existing call sites and tests
// remain unchanged after extracting the parser into a shared package.
func parseLinkHeader(header string) string {
	return _paginate.ParseLinkHeader(header)
}
