package syftPackagesExtractor

import (
	"github.com/Checkmarx/containers-types/types"
	"testing"
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
