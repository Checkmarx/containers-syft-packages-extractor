package syftPackagesExtractor

import (
	"context"
	"encoding/json"
	"fmt"
	"regexp"
	"strings"

	"github.com/Checkmarx/containers-types/types"
	"github.com/anchore/go-collections"
	"github.com/anchore/stereoscope"
	"github.com/anchore/stereoscope/pkg/image"
	"github.com/anchore/syft/syft"
	"github.com/anchore/syft/syft/file"
	"github.com/anchore/syft/syft/format"
	"github.com/anchore/syft/syft/format/syftjson"
	"github.com/anchore/syft/syft/linux"
	"github.com/anchore/syft/syft/pkg"
	"github.com/anchore/syft/syft/sbom"
	"github.com/anchore/syft/syft/source"
	"github.com/anchore/syft/syft/source/sourceproviders"
	"github.com/rs/zerolog/log"
)

var specialExtractors = []string{
	"java-archive",
	"maven",
	"ios",
	"pod",
	"cocoapodspkg",
}

// Common platform specifications
const (
	PlatformLinuxAmd64   = "linux/amd64"
	PlatformLinuxArm64   = "linux/arm64"
	PlatformLinuxArm     = "linux/arm"
	PlatformWindowsAmd64 = "windows/amd64"
)

// analyzeImageWithPlatform provides a convenience function for analyzing images with a specific platform.
// This is useful when you need to analyze multi-architecture images for a specific platform.
//
// Example usage:
//
//	result, err := analyzeImageWithPlatform(imageModel, registryOptions, PlatformLinuxAmd64)
//	if err != nil {
//	    // handle error
//	}
//	// process result...
func analyzeImageWithPlatform(imageModel types.ImageModel, registryOptions *image.RegistryOptions, platform string) (*ContainerResolution, error) {
	return analyzeImage(imageModel, registryOptions, platform)
}

// analyzeImage analyzes a container image using syft and stereoscope libraries.
// If platform is empty, it defaults to linux/amd64.
// Platform format should follow Docker convention (e.g., "linux/amd64", "linux/arm64").
//
// The platform parameter is particularly important when analyzing multi-architecture images,
// as it ensures that the correct architecture-specific layers and packages are analyzed.
//
// Supported platform formats:
// - "linux/amd64" - Linux x86-64
// - "linux/arm64" - Linux ARM 64-bit
// - "linux/arm" - Linux ARM 32-bit
// - "windows/amd64" - Windows x86-64
// - "amd64" - Architecture only (OS defaults to linux)
// - "" - Defaults to linux/amd64
func analyzeImage(imageModel types.ImageModel, registryOptions *image.RegistryOptions, platform string) (*ContainerResolution, error) {

	log.Debug().Msgf("image is %s, found in file paths: %s", imageModel.Name, GetImageLocationsPathsString(imageModel))

	// Default to linux/amd64 if no platform is specified
	if platform == "" {
		platform = PlatformLinuxAmd64
		log.Debug().Msgf("No platform specified, defaulting to %s", platform)
	}

	// Validate platform format
	if _, err := image.NewPlatform(platform); err != nil {
		log.Warn().Msgf("Invalid platform '%s' specified, defaulting to %s. Error: %v", platform, PlatformLinuxAmd64, err)
		platform = PlatformLinuxAmd64
	}

	log.Debug().Msgf("Analyzing image %s with platform %s", imageModel.Name, platform)

	// Build stereoscope options
	stereoscopeOptions := []stereoscope.Option{
		stereoscope.WithRegistryOptions(*registryOptions),
		stereoscope.WithPlatform(platform),
	}

	img, err := stereoscope.GetImage(context.Background(), imageModel.Name, stereoscopeOptions...)
	if err != nil {
		return nil, err
	}
	defer img.Cleanup()

	// Build syft source configuration
	sourceConfig := syft.DefaultGetSourceConfig().WithRegistryOptions(registryOptions)

	// Add platform to syft configuration
	platformObj, err := image.NewPlatform(platform)
	if err != nil {
		return nil, fmt.Errorf("failed to create platform object: %w", err)
	}
	sourceConfig = sourceConfig.WithPlatform(platformObj)

	src, err := syft.GetSource(context.Background(), imageModel.Name, sourceConfig)
	if err != nil {
		log.Err(err).Msgf("Could not create image source object.")
		return nil, err
	}

	s, err := getSBOM(src, true)
	if err != nil {
		log.Err(err).Msgf("Could get image SBOM. image: %s.", imageModel.Name)
		return nil, err
	}

	result := transformSBOMToContainerResolution(s, imageModel)

	return &result, nil
}

// Utility to load Podman credentials and create RegistryOptions
func configureRegistryOptions() (*image.RegistryOptions, error) {
	// Load Podman auth.json
	authConfig, err := LoadPodmanAuth()
	if err != nil {
		return nil, fmt.Errorf("error loading Podman auth.json: %w", err)
	}

	// Generate RegistryCredentials
	credentials, err := CreateRegistryCredentials(authConfig)
	if err != nil {
		return nil, fmt.Errorf("error creating registry credentials: %w", err)
	}

	// Populate RegistryOptions
	registryOptions := &image.RegistryOptions{}
	for _, cred := range credentials {
		registryOptions.Credentials = append(registryOptions.Credentials, cred)
	}

	return registryOptions, nil
}

func allSourceTags() []string {
	return collections.TaggedValueSet[source.Provider]{}.Join(sourceproviders.All("", nil)...).Tags()
}

func getSBOM(src source.Source, saveToFile bool) (sbom.SBOM, error) {
	s, err := syft.CreateSBOM(context.Background(), src, nil)
	if err != nil {
		return sbom.SBOM{}, err
	}

	if saveToFile {
		formatSBOM(*s)
	}
	return *s, nil
}

func formatSBOM(s sbom.SBOM) []byte {
	bytes, err := format.Encode(s, syftjson.NewFormatEncoder())
	if err != nil {
		panic(err)
	}
	return bytes
}

func transformSBOMToContainerResolution(s sbom.SBOM, imageModel types.ImageModel) ContainerResolution {

	imageNameAndTag := strings.Split(imageModel.Name, ":")

	imageResult := ContainerResolution{
		ContainerImage:    ContainerImage{},
		ContainerPackages: []ContainerPackage{},
	}
	var sourceMetadata source.ImageMetadata
	var ok bool

	if sourceMetadata, ok = s.Source.Metadata.(source.ImageMetadata); !ok {
		log.Warn().Msg("Value is not ImageMetadata - can not analyze")
		return imageResult
	}

	distro := getDistro(s.Artifacts.LinuxDistribution)

	extractImage(distro, imageModel, sourceMetadata, imageNameAndTag, &imageResult)
	extractImagePackages(s.Artifacts.Packages, distro, &imageResult)

	return imageResult
}

func extractImage(distro string, imageModel types.ImageModel, sourceMetadata source.ImageMetadata, imageNameAndTag []string, result *ContainerResolution) {

	history := extractHistory(sourceMetadata)
	layerIds := extractLayerIds(history)

	result.ContainerImage = ContainerImage{
		ImageName:      imageNameAndTag[0],
		ImageTag:       imageNameAndTag[1],
		Distribution:   distro,
		ImageHash:      sourceMetadata.ID,
		ImageId:        imageModel.Name,
		Layers:         layerIds,
		History:        history,
		ImageLocations: getImageLocations(imageModel.ImageLocations),
	}
}

func extractImagePackages(packages *pkg.Collection, distro string, result *ContainerResolution) {

	var containerPackages []ContainerPackage

	syftArtifacts := getSyftArtifactsWithoutUnsupportedTypesDuplications(packages)

	for _, containerPackage := range syftArtifacts {

		sourceName, sourceVersion := getPackageRelationships(containerPackage)

		containerPackages = append(containerPackages, ContainerPackage{
			Name:          extractPackageName(containerPackage),
			Version:       containerPackage.Version,
			Distribution:  distro,
			Type:          packageTypeToPackageManager(containerPackage.Type),
			SourceName:    sourceName,
			SourceVersion: sourceVersion,
			Licenses:      extractPackageLicenses(containerPackage),
			LayerIds:      extractPackageLayerIds(containerPackage.Locations),
		})
	}

	result.ContainerPackages = containerPackages
}

func extractPackageName(pack pkg.Package) string {
	for _, t := range specialExtractors {
		if strings.ToLower(string(pack.Type)) == t {
			return extractName(pack.Name, pack.PURL, getGroupId(pack.Metadata))
		}
	}

	return pack.Name
}

func getGroupId(metadata interface{}) string {
	if javaMetadata, ok := metadata.(pkg.JavaArchive); ok {
		if javaMetadata.PomProperties == nil {
			return ""
		}
		return javaMetadata.PomProperties.GroupID
	}
	return ""
}

func outputFormat(groupId, packageName string) string {
	return fmt.Sprintf("%s:%s", groupId, packageName)
}

func extractName(packageName, purl, groupId string) string {
	if groupId != "" {
		if groupId == packageName {
			return packageName
		}
		return outputFormat(groupId, packageName)
	}

	re := regexp.MustCompile(`/(.*?)/`)
	groupIdExistsInPurl := re.FindStringSubmatch(purl)

	if len(groupIdExistsInPurl) < 2 {
		return packageName
	}

	purlGroupId := groupIdExistsInPurl[1]

	if strings.TrimSpace(purlGroupId) == "" {
		return packageName
	}

	if purlGroupId == packageName {
		return packageName
	}

	return outputFormat(purlGroupId, packageName)
}

func getSyftArtifactsWithoutUnsupportedTypesDuplications(packages *pkg.Collection) []pkg.Package {
	var syftArtifacts []pkg.Package

	groupedPackages := make(map[string][]pkg.Package)

	for pack := range packages.Enumerate() {
		if pack.Name != "" && pack.Version != "" {
			key := pack.Name + pack.Version
			groupedPackages[key] = append(groupedPackages[key], pack)
		}
	}

	for _, group := range groupedPackages {
		if len(group) == 1 {
			syftArtifacts = append(syftArtifacts, group[0])
		} else {
			var packageTypes []pkg.Package
			for _, p := range group {
				if packageTypeToPackageManager(p.Type) != string(Unsupported) {
					packageTypes = append(packageTypes, p)
				}
			}
			if len(packageTypes) > 1 {
				log.Warn().Msgf("Found same package id with different types: %v. Selecting first type.", packageTypes)
			}
			if len(packageTypes) > 0 {
				syftArtifacts = append(syftArtifacts, packageTypes[0])
			}
		}
	}

	return syftArtifacts
}

func getPackageRelationships(containerPackage pkg.Package) (string, string) {

	if apkMeta, ok := containerPackage.Metadata.(pkg.ApkDBEntry); ok {
		return getApkSourceName(apkMeta), getApkSourceVersion(containerPackage, apkMeta)
	}
	if debMeta, ok := containerPackage.Metadata.(pkg.DpkgDBEntry); ok {
		return getDebSourceName(debMeta), getDebSourceVersion(containerPackage, debMeta)
	}
	if rpmMeta, ok := containerPackage.Metadata.(pkg.RpmDBEntry); ok {
		return getRpmSourceName(rpmMeta), getRpmSourceVersion(containerPackage, rpmMeta)
	}
	return "", ""
}

func getApkSourceName(apkMeta pkg.ApkDBEntry) string {
	if apkMeta.OriginPackage != "" {
		return apkMeta.OriginPackage
	}
	return ""
}

func getApkSourceVersion(pack pkg.Package, apkMeta pkg.ApkDBEntry) string {
	if apkMeta.OriginPackage != "" {
		if apkMeta.Version != "" {
			return apkMeta.Version
		}
		return pack.Version
	}
	return ""
}

func getDebSourceName(debMeta pkg.DpkgDBEntry) string {
	if debMeta.Source != "" {
		return debMeta.Source
	}
	return ""
}

func getDebSourceVersion(pack pkg.Package, debMeta pkg.DpkgDBEntry) string {
	if debMeta.Source != "" {
		if debMeta.SourceVersion != "" {
			return debMeta.SourceVersion
		}
		return pack.Version
	}
	return ""
}

func getRpmSourceName(rpmMeta pkg.RpmDBEntry) string {
	if rpmMeta.SourceRpm != "" {
		return rpmMeta.SourceRpm
	}
	return ""
}

func getRpmSourceVersion(pack pkg.Package, rpmMeta pkg.RpmDBEntry) string {
	if rpmMeta.SourceRpm != "" {
		if rpmMeta.Version != "" {
			return rpmMeta.Version
		}
		return pack.Version
	}
	return ""
}

func getDistro(release *linux.Release) string {
	if release == nil || release.ID == "" || release.VersionID == "" {
		return types.NoFilePath
	}
	return fmt.Sprintf("%s:%s", release.ID, release.VersionID)
}

func extractPackageLayerIds(locations file.LocationSet) []string {
	var layerIds []string
	for _, l := range locations.ToSlice() {
		layerIds = append(layerIds, removeSha256(l.FileSystemID))
	}
	return layerIds
}

func extractPackageLicenses(p pkg.Package) []string {
	var licenses []string
	for _, l := range p.Licenses.ToSlice() {
		licenses = append(licenses, l.Value)
	}
	return licenses
}

func extractLayerIds(layers []Layer) []string {
	var layerIds []string

	for _, layer := range layers {
		if layer.LayerId != "" {
			layerIds = append(layerIds, layer.LayerId)
		}
	}

	return layerIds
}

func extractHistory(sourceMetadata source.ImageMetadata) []Layer {
	imageConfig := decodeBase64ToJson(sourceMetadata.RawConfig)
	j := 0

	var res []Layer
	for i := 0; i < len(imageConfig.History); i++ {
		isLayerEmpty := imageConfig.History[i].EmptyLayer
		var layerID string
		if !isLayerEmpty {
			layerID = removeSha256(imageConfig.Rootfs.DiffIds[j])
		}

		res = append(res, Layer{
			Order:   i,
			Size:    getSize(layerID, sourceMetadata.Layers),
			LayerId: layerID,
			Command: imageConfig.History[i].CreatedBy,
		})

		if !isLayerEmpty {
			j++
		}
	}
	return res
}

func decodeBase64ToJson(base64Bytes []byte) ImageConfig {
	var imageConfig ImageConfig
	err := json.Unmarshal(base64Bytes, &imageConfig)
	if err != nil {
		return ImageConfig{}
	}
	return imageConfig
}

func removeSha256(str string) string {
	if strings.TrimSpace(str) == "" {
		return str
	}
	return regexp.MustCompile(`^sha256:`).ReplaceAllString(str, "")
}

func getSize(layerId string, layers []source.LayerMetadata) int64 {
	for _, layer := range layers {
		if removeSha256(layer.Digest) == layerId {
			return layer.Size
		}
	}
	return 0
}

func getImageLocations(imageLocations []types.ImageLocation) []ImageLocation {
	var slice []ImageLocation
	for _, location := range imageLocations {
		slice = append(slice, ImageLocation{
			Origin:     location.Origin,
			Path:       location.Path,
			FinalStage: location.FinalStage,
		})
	}
	return slice
}

func GetImageLocationsPathsString(imgModel types.ImageModel) string {
	var paths []string
	for _, location := range imgModel.ImageLocations {
		paths = append(paths, location.Path)
	}
	return strings.Join(paths, ", ")
}
