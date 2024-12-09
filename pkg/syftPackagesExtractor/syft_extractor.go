package syftPackagesExtractor

import (
	"github.com/Checkmarx/containers-types/types"
	"github.com/rs/zerolog/log"
	"strings"
)

type SyftPackagesExtractor interface {
	AnalyzeImages(images []types.ImageModel) ([]*ContainerResolution, error)
}

type syftPackagesExtractor struct {
}

func NewSyftPackagesExtractor() SyftPackagesExtractor {
	return &syftPackagesExtractor{}
}

func (spe *syftPackagesExtractor) AnalyzeImages(images []types.ImageModel) ([]*ContainerResolution, error) {
	if images == nil {
		return []*ContainerResolution{}, nil
	}

	var containerResolution []*ContainerResolution

	for _, imageModel := range images {
		log.Debug().Msgf("going to analyze image using syft. image: %s", imageModel.Name)

		tmpResolution, err := analyzeImage(imageModel)
		if err != nil {
			log.Err(err).Msgf("Could not analyze image: %s.", imageModel.Name)
			continue
		}
		containerResolution = append(containerResolution, tmpResolution)
		log.Info().Msgf("successfully analyzed image: %s, found %d packages. image paths: %s", imageModel.Name,
			len(tmpResolution.ContainerPackages), getPaths(imageModel.ImageLocations))

	}

	if containerResolution == nil || len(containerResolution) < 1 {
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
