package syftPackagesExtractor

import (
	"context"
	"strings"
	"time"

	stereoimage "github.com/anchore/stereoscope/pkg/image"
	"github.com/anchore/syft/syft/sbom"
	sourceModule "github.com/anchore/syft/syft/source"
	dockerclient "github.com/docker/docker/client"
	"github.com/google/go-containerregistry/pkg/authn"
	"github.com/google/go-containerregistry/pkg/name"
	v1 "github.com/google/go-containerregistry/pkg/v1"
	"github.com/google/go-containerregistry/pkg/v1/remote"
	"github.com/rs/zerolog/log"
)

// freshnessCheckTimeout bounds the single, lightweight registry manifest HEAD request issued by
// the freshness check. It must stay short: this call is on the hot path of every plain
// image:tag scan and should never meaningfully slow one down.
const freshnessCheckTimeout = 15 * time.Second

// dockerImageInspector is the minimal docker client surface used by the freshness check, kept
// narrow so it can be faked in unit tests without a real daemon.
type dockerImageInspector interface {
	ImageInspect(ctx context.Context, imageID string, inspectOpts ...dockerclient.ImageInspectOption) (dockerImageInspectResponse, error)
	Close() error
}

// dockerImageInspectResponse mirrors the subset of image.InspectResponse this file needs.
type dockerImageInspectResponse struct {
	RepoDigests []string
}

// dockerAPIClient adapts *dockerclient.Client (the real Docker SDK client) to dockerImageInspector.
type dockerAPIClient struct {
	*dockerclient.Client
}

func (d dockerAPIClient) ImageInspect(ctx context.Context, imageID string, inspectOpts ...dockerclient.ImageInspectOption) (dockerImageInspectResponse, error) {
	resp, err := d.Client.ImageInspect(ctx, imageID, inspectOpts...)
	if err != nil {
		return dockerImageInspectResponse{}, err
	}
	return dockerImageInspectResponse{RepoDigests: resp.RepoDigests}, nil
}

// newDockerImageInspector is overridable in tests. It builds a Docker client the same way
// stereoscope's own daemon provider does (client.FromEnv + API version negotiation), so it
// honours DOCKER_HOST and friends identically.
var newDockerImageInspector = func() (dockerImageInspector, error) {
	cli, err := dockerclient.NewClientWithOpts(dockerclient.FromEnv, dockerclient.WithAPIVersionNegotiation())
	if err != nil {
		return nil, err
	}
	return dockerAPIClient{cli}, nil
}

// remoteHeadFunc is overridable in tests. It performs a single, lightweight manifest HEAD
// request against a registry, without pulling any image content.
var remoteHeadFunc = func(ref name.Reference, options ...remote.Option) (*v1.Descriptor, error) {
	return remote.Head(ref, options...)
}

// registryPrefixSourceHint is the syft/stereoscope source hint name for the registry provider.
// It intentionally matches the "registry" scheme used elsewhere (e.g. stereoscope.ExtractSchemeSource).
const registryPrefixSourceHint = "registry"

// resolveSourceHintForFreshness decides whether analyzeImage should force the registry source
// (rather than letting stereoscope prefer the Docker daemon) because the locally cached copy of
// a tagged image is stale compared to the registry.
//
// It only ever returns a non-empty hint (the string "registry") when it can positively prove a
// digest mismatch. Every other outcome - the daemon being unreachable, the image missing
// locally, having no RepoDigests for this repository (e.g. an image built locally and never
// pushed/pulled), or the registry HEAD request failing for any reason (network, auth, 404,
// air-gapped) - is treated as a no-op, preserving today's daemon-first behavior.
//
// This check only makes sense for a plain tagged image reference (no explicit source scheme,
// not a tar/OCI archive/dir/file path); callers are expected to only invoke it in that case.
func resolveSourceHintForFreshness(imageNameForAnalysis string, registryOptions *stereoimage.RegistryOptions) string {
	ref, err := name.ParseReference(imageNameForAnalysis)
	if err != nil {
		log.Debug().Err(err).Msgf("Freshness check: could not parse image reference '%s', skipping", imageNameForAnalysis)
		return ""
	}

	localDigest, ok := localRepoDigest(imageNameForAnalysis, ref)
	if !ok {
		return ""
	}

	remoteDigest, err := remoteManifestDigest(ref, registryOptions)
	if err != nil {
		log.Warn().Err(err).Msgf("Freshness check: failed to fetch registry manifest digest for '%s', keeping local image", imageNameForAnalysis)
		return ""
	}

	if remoteDigest == localDigest {
		log.Debug().Msgf("Freshness check: local image '%s' matches registry digest %s, using local image", imageNameForAnalysis, localDigest)
		return ""
	}

	log.Info().Msgf("Freshness check: local image '%s' is stale (local digest: %s, registry digest: %s), forcing registry source", imageNameForAnalysis, localDigest, remoteDigest)
	return registryPrefixSourceHint
}

// localRepoDigest inspects the image in the local Docker daemon and returns the RepoDigest that
// matches the given reference's repository, if any. The second return value is false whenever no
// freshness comparison can or should be made (daemon unreachable, image not present locally, or
// no RepoDigests recorded for this repository).
func localRepoDigest(imageNameForAnalysis string, ref name.Reference) (string, bool) {
	inspector, err := newDockerImageInspector()
	if err != nil {
		log.Debug().Err(err).Msg("Freshness check: Docker daemon unavailable, skipping")
		return "", false
	}
	defer func() {
		_ = inspector.Close()
	}()

	ctx, cancel := context.WithTimeout(context.Background(), freshnessCheckTimeout)
	defer cancel()

	inspectResult, err := inspector.ImageInspect(ctx, imageNameForAnalysis)
	if err != nil {
		log.Debug().Err(err).Msgf("Freshness check: image '%s' not present locally or daemon unreachable, skipping", imageNameForAnalysis)
		return "", false
	}

	if len(inspectResult.RepoDigests) == 0 {
		log.Debug().Msgf("Freshness check: local image '%s' has no RepoDigests (built locally, never pushed/pulled), using local image", imageNameForAnalysis)
		return "", false
	}

	repoName := ref.Context().Name()
	for _, repoDigest := range inspectResult.RepoDigests {
		digestRepo, digest, found := strings.Cut(repoDigest, "@")
		if !found {
			continue
		}
		if digestRepo == repoName {
			return digest, true
		}
	}

	log.Debug().Msgf("Freshness check: no RepoDigests for repository '%s' found among local image's RepoDigests %v, using local image", repoName, inspectResult.RepoDigests)
	return "", false
}

// remoteManifestDigest issues a single manifest HEAD request against the registry, using the
// same credentials the registry provider would use: the configured RegistryOptions credentials
// if any, falling back to the default keychain (docker config, ambient cloud credentials, etc).
func remoteManifestDigest(ref name.Reference, registryOptions *stereoimage.RegistryOptions) (string, error) {
	ctx, cancel := context.WithTimeout(context.Background(), freshnessCheckTimeout)
	defer cancel()

	options := []remote.Option{remote.WithContext(ctx)}

	var authenticator authn.Authenticator
	if registryOptions != nil {
		authenticator = registryOptions.Authenticator(ref.Context().RegistryStr())
	}
	if authenticator != nil {
		options = append(options, remote.WithAuth(authenticator))
	} else {
		options = append(options, remote.WithAuthFromKeychain(authn.DefaultKeychain))
	}

	descriptor, err := remoteHeadFunc(ref, options...)
	if err != nil {
		return "", err
	}

	return descriptor.Digest.String(), nil
}

// logResolvedImageSource logs which source (daemon or registry) was actually used to read the
// image, along with its resolved digest, so future support cases can tell the two apart.
func logResolvedImageSource(imageName, sourceHint string, s sbom.SBOM) {
	sourceUsed := sourceHint
	if sourceUsed == "" {
		sourceUsed = "daemon (default provider order)"
	}

	sourceMetadata, ok := s.Source.Metadata.(sourceModule.ImageMetadata)
	if !ok {
		log.Debug().Msgf("Resolved image %s using source hint '%s' (no image metadata available)", imageName, sourceUsed)
		return
	}

	log.Info().Msgf("Resolved image %s using source '%s': imageID=%s, manifestDigest=%s", imageName, sourceUsed, sourceMetadata.ID, sourceMetadata.ManifestDigest)
}
