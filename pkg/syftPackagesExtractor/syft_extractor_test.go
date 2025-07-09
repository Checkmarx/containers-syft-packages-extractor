package syftPackagesExtractor

import (
	"encoding/json"
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

		// Define expected values for the valid image
		expectedValues := map[string]struct {
			Layers         int
			Packages       int
			ImageLocations int
		}{
			"rabbitmq:3": {Layers: 9, Packages: 101, ImageLocations: 1},
		}

		checkResults(t, resolutions, expectedValues)
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
