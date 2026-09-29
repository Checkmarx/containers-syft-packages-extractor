package syftPackagesExtractor

import (
	"context"
	"errors"
	"testing"

	stereoimage "github.com/anchore/stereoscope/pkg/image"
	dockerclient "github.com/docker/docker/client"
	"github.com/google/go-containerregistry/pkg/name"
	v1 "github.com/google/go-containerregistry/pkg/v1"
	"github.com/google/go-containerregistry/pkg/v1/remote"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// fakeInspector is a test double for dockerImageInspector.
type fakeInspector struct {
	repoDigests []string
	inspectErr  error
	closed      bool
}

func (f *fakeInspector) ImageInspect(_ context.Context, _ string, _ ...dockerclient.ImageInspectOption) (dockerImageInspectResponse, error) {
	if f.inspectErr != nil {
		return dockerImageInspectResponse{}, f.inspectErr
	}
	return dockerImageInspectResponse{RepoDigests: f.repoDigests}, nil
}

func (f *fakeInspector) Close() error {
	f.closed = true
	return nil
}

// withFakeDocker swaps newDockerImageInspector for the duration of the test.
func withFakeDocker(t *testing.T, inspector dockerImageInspector, creationErr error) {
	t.Helper()
	original := newDockerImageInspector
	newDockerImageInspector = func() (dockerImageInspector, error) {
		if creationErr != nil {
			return nil, creationErr
		}
		return inspector, nil
	}
	t.Cleanup(func() {
		newDockerImageInspector = original
	})
}

// withFakeRemoteHead swaps remoteHeadFunc for the duration of the test.
func withFakeRemoteHead(t *testing.T, fn func(ref name.Reference, options ...remote.Option) (*v1.Descriptor, error)) {
	t.Helper()
	original := remoteHeadFunc
	remoteHeadFunc = fn
	t.Cleanup(func() {
		remoteHeadFunc = original
	})
}

func digestDescriptor(t *testing.T, digest string) *v1.Descriptor {
	t.Helper()
	h, err := v1.NewHash(digest)
	require.NoError(t, err)
	return &v1.Descriptor{Digest: h}
}

const (
	testDigestA = "sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
	testDigestB = "sha256:bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb"
)

func TestResolveSourceHintForFreshness_DigestsMatch_KeepsDaemon(t *testing.T) {
	withFakeDocker(t, &fakeInspector{
		repoDigests: []string{"ghcr.io/org/img@" + testDigestA},
	}, nil)
	withFakeRemoteHead(t, func(_ name.Reference, _ ...remote.Option) (*v1.Descriptor, error) {
		return digestDescriptor(t, testDigestA), nil
	})

	hint := resolveSourceHintForFreshness("ghcr.io/org/img:tag", &stereoimage.RegistryOptions{})

	assert.Equal(t, "", hint)
}

func TestResolveSourceHintForFreshness_DigestsMismatch_ForcesRegistry(t *testing.T) {
	withFakeDocker(t, &fakeInspector{
		repoDigests: []string{"ghcr.io/org/img@" + testDigestA},
	}, nil)
	withFakeRemoteHead(t, func(_ name.Reference, _ ...remote.Option) (*v1.Descriptor, error) {
		return digestDescriptor(t, testDigestB), nil
	})

	hint := resolveSourceHintForFreshness("ghcr.io/org/img:tag", &stereoimage.RegistryOptions{})

	assert.Equal(t, registryPrefixSourceHint, hint)
}

func TestResolveSourceHintForFreshness_NoRepoDigests_KeepsDaemon(t *testing.T) {
	remoteHeadCalled := false
	withFakeDocker(t, &fakeInspector{repoDigests: nil}, nil)
	withFakeRemoteHead(t, func(_ name.Reference, _ ...remote.Option) (*v1.Descriptor, error) {
		remoteHeadCalled = true
		return digestDescriptor(t, testDigestA), nil
	})

	hint := resolveSourceHintForFreshness("ghcr.io/org/img:tag", &stereoimage.RegistryOptions{})

	assert.Equal(t, "", hint)
	assert.False(t, remoteHeadCalled, "registry should not be contacted when there are no local RepoDigests")
}

func TestResolveSourceHintForFreshness_NoMatchingRepoDigest_KeepsDaemon(t *testing.T) {
	// RepoDigests present, but for a different repository than the one being analyzed.
	withFakeDocker(t, &fakeInspector{
		repoDigests: []string{"ghcr.io/org/other-img@" + testDigestA},
	}, nil)
	withFakeRemoteHead(t, func(_ name.Reference, _ ...remote.Option) (*v1.Descriptor, error) {
		return digestDescriptor(t, testDigestB), nil
	})

	hint := resolveSourceHintForFreshness("ghcr.io/org/img:tag", &stereoimage.RegistryOptions{})

	assert.Equal(t, "", hint)
}

func TestResolveSourceHintForFreshness_DaemonUnavailable_KeepsDaemon(t *testing.T) {
	remoteHeadCalled := false
	withFakeDocker(t, nil, errors.New("cannot connect to the Docker daemon"))
	withFakeRemoteHead(t, func(_ name.Reference, _ ...remote.Option) (*v1.Descriptor, error) {
		remoteHeadCalled = true
		return digestDescriptor(t, testDigestA), nil
	})

	hint := resolveSourceHintForFreshness("ghcr.io/org/img:tag", &stereoimage.RegistryOptions{})

	assert.Equal(t, "", hint)
	assert.False(t, remoteHeadCalled, "registry should not be contacted when the daemon is unavailable")
}

func TestResolveSourceHintForFreshness_ImageNotPresentLocally_KeepsDaemon(t *testing.T) {
	remoteHeadCalled := false
	withFakeDocker(t, &fakeInspector{inspectErr: errors.New("No such image")}, nil)
	withFakeRemoteHead(t, func(_ name.Reference, _ ...remote.Option) (*v1.Descriptor, error) {
		remoteHeadCalled = true
		return digestDescriptor(t, testDigestA), nil
	})

	hint := resolveSourceHintForFreshness("ghcr.io/org/img:tag", &stereoimage.RegistryOptions{})

	assert.Equal(t, "", hint)
	assert.False(t, remoteHeadCalled, "registry should not be contacted when the image is not present locally")
}

func TestResolveSourceHintForFreshness_RemoteHeadFails_KeepsDaemon(t *testing.T) {
	withFakeDocker(t, &fakeInspector{
		repoDigests: []string{"ghcr.io/org/img@" + testDigestA},
	}, nil)
	withFakeRemoteHead(t, func(_ name.Reference, _ ...remote.Option) (*v1.Descriptor, error) {
		return nil, errors.New("network unreachable")
	})

	hint := resolveSourceHintForFreshness("ghcr.io/org/img:tag", &stereoimage.RegistryOptions{})

	assert.Equal(t, "", hint)
}

func TestFreshnessCheckSkippedForNonTaggedInputs(t *testing.T) {
	// analyzeImage only calls resolveSourceHintForFreshness when sourceHint == "" and the image
	// is a plain tagged reference. Tar files, OCI archives/dirs, and explicit scheme prefixes
	// must never reach it - mirrors the guard clause in analyzeImage.
	tests := []struct {
		name       string
		sourceHint string
		imageName  string
	}{
		{name: "docker-archive tar file", sourceHint: "docker-archive", imageName: "/path/to/image.tar"},
		{name: "oci-archive tar file", sourceHint: "oci-archive", imageName: "/path/to/image.tar"},
		{name: "oci-dir path", sourceHint: "oci-dir", imageName: "/path/to/oci-dir"},
		{name: "plain .tar path, no scheme", sourceHint: "", imageName: "/path/to/image.tar"},
		{name: "explicit registry scheme", sourceHint: "registry", imageName: "ghcr.io/org/img:tag"},
		{name: "explicit docker scheme", sourceHint: "docker", imageName: "ghcr.io/org/img:tag"},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			shouldCheck := test.sourceHint == "" && isTaggedImageFormat(test.imageName)
			assert.False(t, shouldCheck, "freshness check should be skipped for %s", test.name)
		})
	}
}

func TestFreshnessCheckAppliesForPlainTaggedImage(t *testing.T) {
	assert.True(t, "" == "" && isTaggedImageFormat("ghcr.io/org/img:tag"))
}
