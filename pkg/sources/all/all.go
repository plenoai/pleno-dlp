// Package all blank-imports every concrete source so their init() registers
// against pkg/sources.registry. Per ADR-0002, the CLI binary blank-imports
// this package; new sources add a single import line below.
package all

import (
	_ "github.com/plenoai/pleno-dlp/pkg/sources/filesystem"
)
