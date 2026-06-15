// Package all blank-imports every concrete source so their init() registers
// against pkg/sources.registry. The CLI binary blank-imports this package;
// new sources add a single import line below.
package all

import (
	// SaaS connectors register against pkg/connectors's registry through
	// init(). Importing the package once pulls in every connector and
	// every stub.
	_ "github.com/plenoai/pleno-dlp/pkg/connectors"

	_ "github.com/plenoai/pleno-dlp/pkg/sources/filesystem"
	_ "github.com/plenoai/pleno-dlp/pkg/sources/gcs"
	_ "github.com/plenoai/pleno-dlp/pkg/sources/git"
	_ "github.com/plenoai/pleno-dlp/pkg/sources/s3"
	_ "github.com/plenoai/pleno-dlp/pkg/sources/sqldump"
	_ "github.com/plenoai/pleno-dlp/pkg/sources/stdin"
)
