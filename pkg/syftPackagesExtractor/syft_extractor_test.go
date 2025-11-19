package syftPackagesExtractor

import (
	"encoding/json"
	"errors"
	"testing"

	"github.com/Checkmarx/containers-types/types"
	"github.com/stretchr/testify/assert"
)

func TestSyftExtractor(t *testing.T) {
	extractor := &syftPackagesExtractor{}

	t.Run("ValidImages", func(t *testing.T) {
		// Define a list of valid images for testing
		images := []types.ImageModel{
			{Name: "rabbitmq:3", ImageLocations: []types.ImageLocation{{Origin: types.DockerFileOrigin, Path: "/path/to/Dockerfile"}}},
			{Name: "golang:1.21.5-alpine3.18", ImageLocations: []types.ImageLocation{{Origin: types.UserInput, Path: "None"}}},
		}

		resolutions, err := extractor.AnalyzeImages(images)
		if err != nil {
			t.Errorf("Error analyzing images: %v", err)
		}
		expectedValues := map[string]struct {
			Layers         int
			Packages       int
			ImageLocations int
		}{
			"rabbitmq:3":               {Layers: 9, Packages: 101, ImageLocations: 1},
			"golang:1.21.5-alpine3.18": {Layers: 4, Packages: 38, ImageLocations: 1},
		}

		checkResults(t, resolutions, expectedValues)

	})

	t.Run("ValidPrivateImage", func(t *testing.T) {
		t.Skip("Skipping this test if you don't have podman credentials file")
		// Define a list of valid images for testing
		images := []types.ImageModel{
			{Name: "ghcr.io/checkmarx-containers/alpine-test:3.15", ImageLocations: []types.ImageLocation{{Origin: types.UserInput, Path: "None"}}},
		}

		resolutions, err := extractor.AnalyzeImages(images)
		if err != nil {
			t.Errorf("Error analyzing images: %v", err)
		}
		expectedValues := map[string]struct {
			Layers         int
			Packages       int
			ImageLocations int
		}{
			"ghcr.io/checkmarx-containers/alpine-test:3.15": {Layers: 1, Packages: 14, ImageLocations: 1},
		}

		checkResults(t, resolutions, expectedValues)
	})

	t.Run("ImageWithTwoFileLocations", func(t *testing.T) {
		// Define a list of images with two file locations
		images := []types.ImageModel{
			{Name: "rabbitmq:3", ImageLocations: []types.ImageLocation{{Origin: types.DockerFileOrigin, Path: "/path/to/Dockerfile"}, {Origin: types.DockerFileOrigin, Path: "/path/to/AnotherDockerfile"}}},
		}

		resolutions, err := extractor.AnalyzeImages(images)
		if err != nil {
			t.Errorf("Error analyzing images: %v", err)
		}

		// Define expected values for the image with two file locations
		expectedValues := map[string]struct {
			Layers         int
			Packages       int
			ImageLocations int
		}{
			"rabbitmq:3": {Layers: 9, Packages: 101, ImageLocations: 2},
		}

		checkResults(t, resolutions, expectedValues)
	})

	t.Run("ImageFailure", func(t *testing.T) {
		// Define a list of images with a failing image
		images := []types.ImageModel{
			{Name: "invalid-image:latest", ImageLocations: []types.ImageLocation{{Origin: types.DockerFileOrigin, Path: "/path/to/Dockerfile"}}},
		}

		_, err := extractor.AnalyzeImages(images)
		if err != nil {
			t.Error("Expected error not be raised")
		}
	})

	t.Run("ImagesAreNil", func(t *testing.T) {

		resolutions, err := extractor.AnalyzeImages(nil)
		if err != nil {
			t.Errorf("Error analyzing images: %v", err)
		}

		if len(resolutions) != 0 {
			t.Errorf("Resolutionshould be empty")
		}
	})

	t.Run("ImagesAreEmpty", func(t *testing.T) {

		images := []types.ImageModel{}

		resolutions, err := extractor.AnalyzeImages(images)
		if err != nil {
			t.Errorf("Error analyzing images: %v", err)
		}

		if len(resolutions) != 0 {
			t.Errorf("Resolutionshould be empty")
		}
	})

	t.Run("OneImageSuccessOneImageFailure", func(t *testing.T) {
		// Define a list of images with one valid and one failing image
		images := []types.ImageModel{
			{Name: "rabbitmq:3", ImageLocations: []types.ImageLocation{{Origin: types.DockerFileOrigin, Path: "/path/to/Dockerfile"}}},
			{Name: "invalid-image:latest", ImageLocations: []types.ImageLocation{{Origin: types.DockerFileOrigin, Path: "/path/to/Dockerfile"}}},
		}

		resolutions, err := extractor.AnalyzeImages(images)
		if err != nil {
			t.Errorf("Error analyzing images: %v", err)
		}

		// Expect 2 resolutions: one successful and one failed
		assert.Equal(t, 2, len(resolutions), "Should have 2 resolutions (1 success, 1 failed)")

		// Find and check the successful resolution
		var successResolution *ContainerResolution
		var failedResolution *ContainerResolution
		for _, resolution := range resolutions {
			if resolution.ContainerImage.Status == "Resolved" {
				successResolution = resolution
			} else if resolution.ContainerImage.Status == "Failed" {
				failedResolution = resolution
			}
		}

		// Check the successful resolution
		assert.NotNil(t, successResolution, "Should have one successful resolution")
		assert.Equal(t, "rabbitmq:3", successResolution.ContainerImage.ImageId)
		assert.Equal(t, 9, len(successResolution.ContainerImage.Layers))
		assert.Equal(t, 101, len(successResolution.ContainerPackages))
		assert.Equal(t, 1, len(successResolution.ContainerImage.ImageLocations))

		// Check the failed resolution
		assert.NotNil(t, failedResolution, "Should have one failed resolution")
		assert.Equal(t, "Failed", failedResolution.ContainerImage.Status)
		assert.NotEmpty(t, failedResolution.ContainerImage.ScanError)
		assert.Equal(t, 0, len(failedResolution.ContainerPackages))
		assert.Equal(t, 0, len(failedResolution.ContainerImage.Layers))
	})
}

func TestContainerResolutionIncludesCycloneDxSBOM(t *testing.T) {
	// Test that the ContainerResolution includes the CycloneDxSBOM field
	resolution := ContainerResolution{
		ContainerImage: ContainerImage{
			ImageName: "test-image",
			ImageTag:  "latest",
		},
		ContainerPackages: []ContainerPackage{},
		CycloneDxSBOM:     "H4sIAAAAAAAAA...", // Example base64 encoded gzipped content
	}

	// Convert to JSON to verify the field is serialized
	jsonData, err := json.Marshal(resolution)
	assert.NoError(t, err)

	// Verify the JSON contains the cycloneDxSBOM field
	var result map[string]interface{}
	err = json.Unmarshal(jsonData, &result)
	assert.NoError(t, err)

	// Check that the cycloneDxSBOM field exists
	cycloneDxSBOM, exists := result["cycloneDxSBOM"]
	assert.True(t, exists, "cycloneDxSBOM field should exist in JSON output")
	assert.NotNil(t, cycloneDxSBOM, "cycloneDxSBOM should not be nil")
	assert.Equal(t, "H4sIAAAAAAAAA...", cycloneDxSBOM, "cycloneDxSBOM value should match")
}

func TestCycloneDxSBOMFieldOmittedWhenEmpty(t *testing.T) {
	// Test that the CycloneDxSBOM field is omitted when empty
	resolution := ContainerResolution{
		ContainerImage: ContainerImage{
			ImageName: "test-image",
			ImageTag:  "latest",
		},
		ContainerPackages: []ContainerPackage{},
		CycloneDxSBOM:     "", // Empty CycloneDxSBOM
	}

	// Convert to JSON
	jsonData, err := json.Marshal(resolution)
	assert.NoError(t, err)

	// Verify the JSON does not contain the cycloneDxSBOM field when empty
	var result map[string]interface{}
	err = json.Unmarshal(jsonData, &result)
	assert.NoError(t, err)

	// Check that the cycloneDxSBOM field does not exist when empty
	_, exists := result["cycloneDxSBOM"]
	assert.False(t, exists, "cycloneDxSBOM field should not exist in JSON output when empty")
}

// TestUnresolvedImages tests that images that fail to resolve are included with "Failed" status
func TestUnresolvedImages(t *testing.T) {
	extractor := &syftPackagesExtractor{}

	// Test with a mix of valid and invalid images
	images := []types.ImageModel{
		{Name: "nonexistent-private-registry.example.com/private-image:latest", ImageLocations: []types.ImageLocation{{Origin: types.DockerFileOrigin, Path: "/path/to/Dockerfile"}}},
		{Name: "invalid-image-name-without-registry:tag", ImageLocations: []types.ImageLocation{{Origin: types.UserInput, Path: "None"}}},
	}

	resolutions, err := extractor.AnalyzeImages(images)
	assert.NoError(t, err, "AnalyzeImages should not return an error even if individual images fail")
	assert.Equal(t, 2, len(resolutions), "Should have 2 resolutions (both failed)")

	// Check that all resolutions have "Failed" status in ContainerImage
	for _, resolution := range resolutions {
		assert.Equal(t, "Failed", resolution.ContainerImage.Status, "Failed images should have 'Failed' status in ContainerImage")
		assert.NotEmpty(t, resolution.ContainerImage.ScanError, "Failed images should have a scan error in ContainerImage")
		assert.Equal(t, 0, len(resolution.ContainerPackages), "Failed images should have no packages")
		assert.Equal(t, 0, len(resolution.ContainerImage.Layers), "Failed images should have no layers")
		assert.NotEmpty(t, resolution.ContainerImage.ImageName, "Failed images should still have image name")
	}
}

// TestErrorMapping tests that Syft errors are correctly mapped to custom error messages
func TestErrorMapping(t *testing.T) {
	tests := []struct {
		name          string
		inputError    string
		expectedError string
	}{
		{
			name:          "TooManyRequests error",
			inputError:    "error: toomanyrequests: exceeded rate limit",
			expectedError: "Exceeded request limit to Docker Hub",
		},
		{
			name:          "Could not parse reference error",
			inputError:    "could not parse reference: invalid format at https://registry.example.com/v2/",
			expectedError: "Unable to parse image name or tag. Registry: registry.example.com",
		},
		{
			name:          "MANIFEST_UNKNOWN error",
			inputError:    "GET https://index.docker.io/v2/library/nonexistent/manifests/latest: MANIFEST_UNKNOWN: manifest unknown",
			expectedError: "The requested image is not found or is unavailable. Registry: index.docker.io",
		},
		{
			name:          "Authentication is required error",
			inputError:    "GET https://private-registry.example.com/v2/: authentication is required",
			expectedError: "Retrieval from the private repository failed. Verify the credentials used for the integration. Registry: private-registry.example.com",
		},
		{
			name:          "Unauthorized error",
			inputError:    "GET https://registry.example.com/v2/library/image/manifests/tag: UNAUTHORIZED: authentication required",
			expectedError: "Access to the image is restricted. Verify the repository permissions and credentials. Registry: registry.example.com",
		},
		{
			name:          "No child with platform error",
			inputError:    "no child with platform linux/amd64 found in manifest list",
			expectedError: "The image is incompatible with the scanning tool. A Linux/AMD64 version is required.",
		},
		{
			name:          "Unsupported MediaType error",
			inputError:    "unsupported MediaType: application/vnd.oci.image.manifest.v1+json",
			expectedError: "The image format is outdated and unsupported. You may need to update or rebuild the image.",
		},
		{
			name:          "Generic error",
			inputError:    "some random error that doesn't match any pattern",
			expectedError: "Unexpected error occurred during image resolution",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := errors.New(tt.inputError)
			result := mapErrorToCustomMessage(err)
			assert.Contains(t, result, tt.expectedError, "Error message should contain expected text")
		})
	}
}

func checkResults(t *testing.T, resolutions []*ContainerResolution, expectedValues map[string]struct {
	Layers         int
	Packages       int
	ImageLocations int
}) {
	if len(resolutions) != len(expectedValues) {
		t.Errorf("Expected %d results, got %d", len(expectedValues), len(resolutions))
	}

	for _, resolution := range resolutions {
		// Get the expected values for the current resolution
		expected, ok := expectedValues[resolution.ContainerImage.ImageId]
		if !ok {
			t.Errorf("No expected values found for image: %s", resolution.ContainerImage.ImageId)
			continue
		}

		// Check the number of layers
		if len(resolution.ContainerImage.Layers) != expected.Layers {
			t.Errorf("Expected %d layers for image %s, got %d", expected.Layers, resolution.ContainerImage.ImageId, len(resolution.ContainerImage.Layers))
		}

		// Check the number of packages
		if len(resolution.ContainerPackages) != expected.Packages {
			t.Errorf("Expected %d packages for image %s, got %d", expected.Packages, resolution.ContainerImage.ImageId, len(resolution.ContainerPackages))
		}

		// Check the number of image locations
		if len(resolution.ContainerImage.ImageLocations) != expected.ImageLocations {
			t.Errorf("Expected %d image locations for image %s, got %d", expected.ImageLocations, resolution.ContainerImage.ImageId, len(resolution.ContainerImage.ImageLocations))
		}
	}
}
