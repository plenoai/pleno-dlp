// Package all blank-imports every concrete detector so that their init()
// functions run and register themselves with pkg/detectors. Per ADR-0002, the
// CLI binary blank-imports this package; new detectors add one line here.
package all

import (
	_ "github.com/plenoai/pleno-dlp/pkg/detectors/anthropic"
	_ "github.com/plenoai/pleno-dlp/pkg/detectors/aws"
	_ "github.com/plenoai/pleno-dlp/pkg/detectors/github"
	_ "github.com/plenoai/pleno-dlp/pkg/detectors/openai"
	_ "github.com/plenoai/pleno-dlp/pkg/detectors/slack"
)
