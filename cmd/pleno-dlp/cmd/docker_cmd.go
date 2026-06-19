package cmd

import (
	"encoding/json"
	"fmt"

	"github.com/spf13/cobra"

	"github.com/plenoai/pleno-dlp/pkg/sources"
)

type dockerFlags struct {
	image        string
	platform     string
	fromDaemon   bool
	username     string
	password     string
	include      []string
	exclude      []string
	maxLayerSize int64
}

var dockerOpts dockerFlags

var scanDockerCmd = &cobra.Command{
	Use:   "docker-image --image <ref>",
	Short: "Scan secrets baked into Docker/OCI image layers and config",
	Long: `Scan a Docker/OCI image for secrets in:
  - image config (ENV, labels, Cmd, Entrypoint)
  - every text file in every image layer

By default the image is pulled from the registry using keychain auth
(docker config / credential helpers). Use --from-daemon to load a
locally cached image from the Docker daemon instead.

Examples:
  pleno-dlp scan docker-image --image alpine:3.20
  pleno-dlp scan docker-image --image myregistry.io/app:prod --platform linux/amd64
  pleno-dlp scan docker-image --image myapp:dev --from-daemon`,
	Args: cobra.NoArgs,
	RunE: runScanDocker,
}

func init() {
	scanDockerCmd.Flags().StringVar(&dockerOpts.image, "image", "", "image reference (e.g. docker.io/library/alpine:3.20)")
	scanDockerCmd.Flags().StringVar(&dockerOpts.platform, "platform", "", "platform to pull for multi-arch images (e.g. linux/amd64)")
	scanDockerCmd.Flags().BoolVar(&dockerOpts.fromDaemon, "from-daemon", false, "load image from local Docker daemon instead of registry")
	scanDockerCmd.Flags().StringVar(&dockerOpts.username, "username", "", "registry username (default: keychain / docker config)")
	scanDockerCmd.Flags().StringVar(&dockerOpts.password, "password", "", "registry password")
	scanDockerCmd.Flags().StringSliceVar(&dockerOpts.include, "include", nil, "glob(s) to include (matched against layer file paths and basenames)")
	scanDockerCmd.Flags().StringSliceVar(&dockerOpts.exclude, "exclude", nil, "glob(s) to exclude")
	scanDockerCmd.Flags().Int64Var(&dockerOpts.maxLayerSize, "max-layer-size", 0, "skip layers larger than this many bytes (0 = default 500 MiB)")
	_ = scanDockerCmd.MarkFlagRequired("image")
}

func runScanDocker(cmd *cobra.Command, _ []string) error {
	src := sources.New(sources.SourceDockerImage)
	if src == nil {
		return fmt.Errorf("docker-image source is not registered (missing pkg/sources/all import?)")
	}
	cfg, err := json.Marshal(map[string]any{
		"image":          dockerOpts.image,
		"platform":       dockerOpts.platform,
		"from_daemon":    dockerOpts.fromDaemon,
		"username":       dockerOpts.username,
		"password":       dockerOpts.password,
		"include":        dockerOpts.include,
		"exclude":        dockerOpts.exclude,
		"max_layer_size": dockerOpts.maxLayerSize,
	})
	if err != nil {
		return fmt.Errorf("encode source config: %w", err)
	}
	return runScanCommon(cmd, src, cfg, "docker-image")
}
