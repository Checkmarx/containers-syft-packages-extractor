package syftPackagesExtractor

import (
	"os"
	"strings"

	"github.com/Checkmarx/containers-types/types"
	"github.com/anchore/stereoscope"
	"github.com/anchore/stereoscope/pkg/image"
	"github.com/rs/zerolog/log"
	_ "modernc.org/sqlite"
)

type SyftPackagesExtractor interface {
	AnalyzeImages(images []types.ImageModel) ([]*ContainerResolution, error)
	AnalyzeImagesWithPlatform(images []types.ImageModel, platform string) ([]*ContainerResolution, error)
}

type syftPackagesExtractor struct {
}

func NewSyftPackagesExtractor() SyftPackagesExtractor {
	return &syftPackagesExtractor{}
}

func (spe *syftPackagesExtractor) AnalyzeImages(images []types.ImageModel) ([]*ContainerResolution, error) {
	return spe.AnalyzeImagesWithPlatform(images, "")
}

func (spe *syftPackagesExtractor) AnalyzeImagesWithPlatform(images []types.ImageModel, platform string) ([]*ContainerResolution, error) {
	if images == nil {
		return []*ContainerResolution{}, nil
	}

	var containerResolution []*ContainerResolution

	defer func() {
		stereoscope.Cleanup()
		log.Info().Msgf("cleanup temp folder (%v/stereoscope*)", os.TempDir())
	}()

	// Step 1: Load Podman credentials and configure RegistryOptions
	registryOptions, err := configureRegistryOptions()
	if err != nil {
		log.Info().Msg("No credentials found for Podman, proceeding without them.")
		registryOptions = &image.RegistryOptions{}
	}

	for _, imageModel := range images {
		log.Debug().Msgf("going to analyze image using syft. image: %s", imageModel.Name)

		tmpResolution, err := analyzeImage(imageModel, registryOptions, platform)
		if err != nil {
			log.Err(err).Msgf("Could not analyze image: %s.", imageModel.Name)
			// Create an unresolved entry for the failed image
			unresolvedResolution := createUnresolvedResolution(imageModel, err)
			containerResolution = append(containerResolution, unresolvedResolution)
			log.Info().Msgf("Added unresolved entry for image: %s. Error: %s", imageModel.Name, err.Error())
			continue
		}
		// Mark successfully resolved images
		tmpResolution.ContainerImage.Status = "Resolved"
		containerResolution = append(containerResolution, tmpResolution)
		log.Info().Msgf("successfully analyzed image: %s, found %d packages. image paths: %s", imageModel.Name,
			len(tmpResolution.ContainerPackages), getPaths(imageModel.ImageLocations))

	}

	if len(containerResolution) < 1 {
		return []*ContainerResolution{}, nil
	}

	return containerResolution, nil
}

func getPaths(locations []types.ImageLocation) string {
	var paths []string
	for _, location := range locations {
		paths = append(paths, location.Path)
	}
	return strings.Join(paths, ",")
}
