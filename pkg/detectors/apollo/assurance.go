package apollo

import "github.com/plenoai/pleno-dlp/pkg/detectors"

func (Scanner) MaxVerificationAssurance() detectors.VerificationAssurance {
	return detectors.AssuranceProviderConfirmed
}

var _ detectors.VerificationPolicy = Scanner{}
