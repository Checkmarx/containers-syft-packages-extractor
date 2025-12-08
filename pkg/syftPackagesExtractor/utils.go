package syftPackagesExtractor

import (
	"archive/tar"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"os"
	"regexp"
	"strings"

	"github.com/Checkmarx/containers-types/types"
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

// Container image prefix constants
const (
	dockerPrefix        = "docker:"
	podmanPrefix        = "podman:"
	containerdPrefix    = "containerd:"
	registryPrefix      = "registry:"
	dockerArchivePrefix = "docker-archive:"
	ociArchivePrefix    = "oci-archive:"
	ociDirPrefix        = "oci-dir:"
	filePrefix          = "file:"
)

// isTaggedImageFormat checks if the image name is in a format where platform information is relevant.
// Returns true for daemon images (docker:, podman:, containerd:), registry images, or standard image:tag format.
// Returns false for tar files and archive formats (docker-archive:, oci-archive:, file:, oci-dir:).
func isTaggedImageFormat(imageName string) bool {
	imageLower := strings.ToLower(imageName)

	// Archive formats - platform is not relevant for these
	archivePrefixes := []string{
		dockerArchivePrefix,
		ociArchivePrefix,
		filePrefix,
		ociDirPrefix,
	}

	for _, prefix := range archivePrefixes {
		if strings.HasPrefix(imageLower, prefix) {
			return false
		}
	}

	// Check if it's a tar file
	if strings.HasSuffix(imageLower, ".tar") {
		return false
	}

	// Daemon and registry prefixes - platform is relevant
	daemonPrefixes := []string{
		dockerPrefix,
		podmanPrefix,
		containerdPrefix,
		registryPrefix,
	}

	for _, prefix := range daemonPrefixes {
		if strings.HasPrefix(imageLower, prefix) {
			return true
		}
	}

	// Standard image:tag format (has colon and is not a tar file)
	// This handles cases like nginx:latest, alpine:3.18, registry.io/namespace/image:tag
	return strings.Contains(imageName, ":")
}

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
// If the platform is empty, it defaults to linux/amd64.
// The platform format should follow Docker convention (e.g., "linux/amd64", "linux/arm64").
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

	// Only log platform info for tagged images (not tar files or archives)
	if isTaggedImageFormat(imageModel.Name) {
		log.Debug().Msgf("Analyzing image %s with platform %s", imageModel.Name, platform)
	} else {
		log.Debug().Msgf("Analyzing image %s", imageModel.Name)
	}

	// Extract scheme source if present (e.g., "oci-dir:/path" -> source="oci-dir", cleanInput="/path")
	// This is necessary because stereoscope providers expect paths without the scheme prefix
	sourceHint, cleanImageName := stereoscope.ExtractSchemeSource(imageModel.Name,
		"docker", "podman", "containerd", "registry",
		"docker-archive", "oci-archive", "oci-dir", "file", "dir")

	// Use the clean image name (without scheme prefix) for stereoscope and syft
	imageNameForAnalysis := cleanImageName
	if imageNameForAnalysis == "" {
		imageNameForAnalysis = imageModel.Name
	}

	log.Debug().Msgf("Extracted source hint: '%s', clean image name: '%s'", sourceHint, imageNameForAnalysis)

	// Build stereoscope options
	stereoscopeOptions := []stereoscope.Option{
		stereoscope.WithRegistryOptions(*registryOptions),
		stereoscope.WithPlatform(platform),
	}

	img, err := stereoscope.GetImage(context.Background(), imageNameForAnalysis, stereoscopeOptions...)
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

	// If we have a source hint, configure syft to use that specific source
	if sourceHint != "" {
		sourceConfig = sourceConfig.WithSources(sourceHint)
	}

	src, err := syft.GetSource(context.Background(), imageNameForAnalysis, sourceConfig)
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

	// Skip images with no packages - nothing to analyze
	if len(result.ContainerPackages) == 0 {
		log.Warn().Msgf("Image %s has 0 packages, skipping from containers-resolution.json", imageModel.Name)
		return nil, fmt.Errorf("image has 0 packages, skipping analysis")
	}

	// Generate CycloneDX SBOM
	cycloneDxSBOM, err := generateCycloneDxSBOM(s)
	if err != nil {
		log.Warn().Err(err).Msg("Failed to generate CycloneDX SBOM, continuing without it")
		// Continue without the CycloneDX SBOM if generation fails
	} else {
		result.CycloneDxSBOM = cycloneDxSBOM
	}

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
	registryOptions := &image.RegistryOptions{
		Credentials: credentials,
	}

	return registryOptions, nil
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

// generateCycloneDxSBOM generates a zipped, base64 encoded CycloneDX SBOM
func generateCycloneDxSBOM(s sbom.SBOM) (string, error) {
	// Delegate to the helper function
	return tryGenerateCycloneDxSBOM(s)
}

// DockerManifest represents the structure of manifest.json in Docker tar files
type DockerManifest struct {
	RepoTags []string `json:"RepoTags"`
}

// extractImageNameAndTagFromTar extracts the actual image name and tag from a Docker saved tar file
// by reading the manifest.json file inside the tar archive
func extractImageNameAndTagFromTar(tarFilePath string) (string, string, error) {
	// Strip any scheme prefix (e.g., "file:", "docker-archive:") from the path
	cleanPath := tarFilePath
	for _, prefix := range []string{filePrefix, dockerArchivePrefix, ociArchivePrefix} {
		// Check case-insensitively, but strip using the actual length
		if strings.HasPrefix(strings.ToLower(cleanPath), prefix) {
			cleanPath = cleanPath[len(prefix):] // Skip the prefix length
			break
		}
	}
	cleanPath = strings.TrimSpace(cleanPath)

	log.Info().Msgf("Opening tar file: original='%s', clean='%s'", tarFilePath, cleanPath)

	file, err := os.Open(cleanPath)
	if err != nil {
		return "", "", fmt.Errorf("failed to open tar file %s: %w. Make sure the file exists and is accessible", cleanPath, err)
	}
	defer file.Close()

	tarReader := tar.NewReader(file)

	for {
		header, err := tarReader.Next()
		if err == io.EOF {
			break
		}
		if err != nil {
			return "", "", fmt.Errorf("failed to read tar file: %w. Make sure this is a valid tar file was created with 'save' command (like: 'docker save' or 'podman save')", err)
		}

		// Look for manifest.json file
		if header.Name == "manifest.json" {
			manifestData, err := io.ReadAll(tarReader)
			if err != nil {
				return "", "", fmt.Errorf("failed to read manifest.json: %w. The tar file may be corrupted", err)
			}

			var manifests []DockerManifest
			if err := json.Unmarshal(manifestData, &manifests); err != nil {
				return "", "", fmt.Errorf("failed to parse manifest.json: %w. Make sure this tar file was created with 'save' command (like: 'docker save' or 'podman save')", err)
			}

			// Extract the first repo tag (there should typically be only one)
			if len(manifests) > 0 && len(manifests[0].RepoTags) > 0 {
				repoTag := manifests[0].RepoTags[0]

				// Split the repo:tag format
				lastColonIndex := strings.LastIndex(repoTag, ":")
				if lastColonIndex == -1 {
					// No tag specified in manifest - this is an error case
					return "", "", fmt.Errorf("no tag found in manifest RepoTags: %s. Make sure the image was saved with a tag using 'docker save <image:tag>' or 'podman save <image:tag>'", repoTag)
				}

				imageName := repoTag[:lastColonIndex]
				imageTag := repoTag[lastColonIndex+1:]

				// Normalize the image name by removing registry prefix and library namespace
				// Podman saves images with full path like "docker.io/library/alpine"
				// We want to normalize this to just "alpine"
				imageName = normalizeImageName(imageName)

				return imageName, imageTag, nil
			}
		}
	}

	return "", "", fmt.Errorf("manifest.json not found in tar file or no RepoTags found. Make sure this tar file was created with 'save' command (like: 'docker save' or 'podman save')")
}

// extractImageNameAndTagFromOCIArchive extracts the image name and tag from an OCI archive tar file
// OCI archives (created by buildah/skopeo) contain index.json with annotations instead of manifest.json
// Image name is extracted from the tar filename (part before first underscore, or full name without extension)
// Image tag is extracted from index.json annotations (org.opencontainers.image.ref.name)
func extractImageNameAndTagFromOCIArchive(tarFilePath string) (string, string, error) {
	// Strip the oci-archive: prefix from the path
	cleanPath := tarFilePath
	if strings.HasPrefix(strings.ToLower(cleanPath), ociArchivePrefix) {
		cleanPath = cleanPath[len(ociArchivePrefix):]
	}
	cleanPath = strings.TrimSpace(cleanPath)

	log.Info().Msgf("Opening OCI archive tar file: original='%s', clean='%s'", tarFilePath, cleanPath)

	// Extract image name from filename
	imageName := extractImageNameFromFilename(cleanPath)
	log.Info().Msgf("Extracted image name '%s' from OCI archive filename", imageName)

	// Open tar file to read index.json
	file, err := os.Open(cleanPath)
	if err != nil {
		return "", "", fmt.Errorf("failed to open OCI archive tar file %s: %w. Make sure the file exists and is accessible", cleanPath, err)
	}
	defer file.Close()

	tarReader := tar.NewReader(file)

	// Look for index.json in the tar archive
	for {
		header, err := tarReader.Next()
		if err == io.EOF {
			break
		}
		if err != nil {
			return "", "", fmt.Errorf("failed to read OCI archive tar file: %w. Make sure this is a valid OCI archive created with 'buildah push' or 'skopeo copy'", err)
		}

		// Look for index.json file (OCI format)
		if header.Name == "index.json" {
			indexData, err := io.ReadAll(tarReader)
			if err != nil {
				return "", "", fmt.Errorf("failed to read index.json from OCI archive: %w. The tar file may be corrupted", err)
			}

			var index OCIIndexJSON
			if err := json.Unmarshal(indexData, &index); err != nil {
				return "", "", fmt.Errorf("failed to parse index.json from OCI archive: %w. Make sure this is a valid OCI archive", err)
			}

			// Extract tag from the first manifest's annotations
			if len(index.Manifests) > 0 && index.Manifests[0].Annotations != nil {
				if refName, ok := index.Manifests[0].Annotations["org.opencontainers.image.ref.name"]; ok && refName != "" {
					imageTag := refName
					log.Info().Msgf("Extracted tag '%s' from OCI archive index.json annotation", imageTag)
					return imageName, imageTag, nil
				}
			}

			// No tag annotation found
			return "", "", fmt.Errorf("no image tag found in OCI archive index.json annotations (org.opencontainers.image.ref.name). Please ensure the OCI archive was created with proper tag information using 'buildah push <image> oci-archive:<path>:<tag>' or 'skopeo copy <source> oci-archive:<path>:<tag>'")
		}
	}

	return "", "", fmt.Errorf("index.json not found in OCI archive tar file. Make sure this is a valid OCI archive created with 'buildah push' or 'skopeo copy' using oci-archive: format")
}

// extractImageNameFromFilename extracts the image name from a tar filename
// Rules:
// - If filename contains underscore (_), extract part before first underscore
// - Otherwise, use full filename without extension
// Examples:
//   - "traefik_v2-custom.tar" -> "traefik"
//   - "nginx.tar" -> "nginx"
//   - "mysql_5_6_7.tar" -> "mysql"
//   - "/path/to/myapp_test.tar" -> "myapp"
func extractImageNameFromFilename(filePath string) string {
	// Get just the filename without directory path
	filename := filePath
	if lastSlash := strings.LastIndex(filePath, "/"); lastSlash != -1 {
		filename = filePath[lastSlash+1:]
	}
	if lastBackslash := strings.LastIndex(filename, "\\"); lastBackslash != -1 {
		filename = filename[lastBackslash+1:]
	}

	// Remove .tar extension (and any other extensions)
	if dotIndex := strings.Index(filename, "."); dotIndex != -1 {
		filename = filename[:dotIndex]
	}

	// If filename contains underscore, use part before first underscore
	if underscoreIndex := strings.Index(filename, "_"); underscoreIndex != -1 {
		return filename[:underscoreIndex]
	}

	// Otherwise, use the full filename (without extension)
	return filename
}

// normalizeImageName removes registry prefix and library namespace from image names.
// This is needed because Podman saves images with full paths like "docker.io/library/alpine"
// while we want to display just "alpine".
//
// Examples:
//   - "docker.io/library/alpine" -> "alpine"
//   - "docker.io/myuser/myimage" -> "myuser/myimage"
//   - "gcr.io/project/image" -> "project/image"
//   - "alpine" -> "alpine" (no change)
//   - "myuser/myimage" -> "myuser/myimage" (no change)
func normalizeImageName(imageName string) string {
	// Known registry prefixes to strip
	registryPrefixes := []string{
		"docker.io/",
		"index.docker.io/",
		"registry.hub.docker.com/",
		"ghcr.io/",
		"gcr.io/",
		"quay.io/",
		"registry.gitlab.com/",
	}

	normalized := imageName

	// Strip known registry prefixes
	for _, prefix := range registryPrefixes {
		if strings.HasPrefix(normalized, prefix) {
			normalized = strings.TrimPrefix(normalized, prefix)
			break
		}
	}

	// Strip "library/" prefix (Docker Hub's default namespace for official images)
	// Only strip if it's at the beginning after removing registry prefix
	if strings.HasPrefix(normalized, "library/") {
		normalized = strings.TrimPrefix(normalized, "library/")
	}

	return normalized
}

// createEmptyContainerResolution returns an empty ContainerResolution
func createEmptyContainerResolution() ContainerResolution {
	return ContainerResolution{
		ContainerImage:    ContainerImage{},
		ContainerPackages: []ContainerPackage{},
	}
}

// isCompressedTarFile checks if the filename has a compressed tar extension
func isCompressedTarFile(filename string) bool {
	lowerFilename := strings.ToLower(filename)
	return strings.HasSuffix(lowerFilename, ".tar.gz") ||
		strings.HasSuffix(lowerFilename, ".tar.bz2") ||
		strings.HasSuffix(lowerFilename, ".tar.xz")
}

// parseImageNameAndTag parses an image name and tag from a string, returns empty strings if no tag found
func parseImageNameAndTag(imageString string) (string, string, error) {
	lastColonIndex := strings.LastIndex(imageString, ":")

	if lastColonIndex == len(imageString)-1 || lastColonIndex == -1 {
		// No tag specified
		return "", "", fmt.Errorf("no tag specified in image name: %s", imageString)
	}

	imageName := imageString[:lastColonIndex]
	imageTag := imageString[lastColonIndex+1:]
	return imageName, imageTag, nil
}

// OCIIndexJSON represents the structure of an OCI index.json file
type OCIIndexJSON struct {
	Manifests []OCIManifest `json:"manifests"`
}

// OCIManifest represents a manifest entry in the OCI index
type OCIManifest struct {
	Annotations map[string]string `json:"annotations"`
}

// extractImageNameAndTagFromOCIDir extracts the image name and tag from an OCI directory structure.
// The image name is derived from the folder name, and the tag is read from the index.json annotation.
func extractImageNameAndTagFromOCIDir(ociDirPath string) (string, string, error) {
	// Remove any leading "oci-dir:" prefix if present
	cleanPath := strings.TrimPrefix(ociDirPath, ociDirPrefix)
	cleanPath = strings.TrimSpace(cleanPath)

	// Extract the folder name as the image name
	// For example: "docker.io/library/alpine" -> "alpine"
	imageName := cleanPath
	if strings.Contains(cleanPath, "/") {
		parts := strings.Split(cleanPath, "/")
		imageName = parts[len(parts)-1] // Get the last part
	}

	// Read the index.json file to get the tag from annotations
	indexPath := fmt.Sprintf("%s/index.json", cleanPath)
	indexData, err := os.ReadFile(indexPath)
	if err != nil {
		return "", "", fmt.Errorf("failed to read index.json from OCI directory %s: %w", cleanPath, err)
	}

	var index OCIIndexJSON
	if err := json.Unmarshal(indexData, &index); err != nil {
		return "", "", fmt.Errorf("failed to parse index.json: %w", err)
	}

	// Extract tag from the first manifest's annotations
	imageTag := ""
	if len(index.Manifests) > 0 && index.Manifests[0].Annotations != nil {
		if refName, ok := index.Manifests[0].Annotations["org.opencontainers.image.ref.name"]; ok && refName != "" {
			imageTag = refName
			log.Debug().Msgf("Extracted tag '%s' from OCI index.json annotation", imageTag)
		}
	}

	if imageTag == "" {
		return "", "", fmt.Errorf("no image tag found in OCI index.json annotations (org.opencontainers.image.ref.name). Please ensure the OCI directory was created with proper tag information")
	}

	log.Info().Msgf("Extracted from OCI directory - image name: %s, tag: %s", imageName, imageTag)
	return imageName, imageTag, nil
}

func transformSBOMToContainerResolution(s sbom.SBOM, imageModel types.ImageModel) ContainerResolution {
	imageName := imageModel.Name
	var imageTag string

	log.Debug().Msgf("transformSBOMToContainerResolution called with imageName: %s", imageName)

	// Check if this is an OCI directory source
	if strings.HasPrefix(strings.ToLower(imageName), ociDirPrefix) {
		// This is an OCI directory - extract image name from folder name and tag from index.json
		log.Info().Msgf("Processing OCI directory: %s", imageName)

		actualImageName, actualImageTag, err := extractImageNameAndTagFromOCIDir(imageName)
		if err != nil {
			log.Warn().Err(err).Msgf("Failed to extract image name and tag from OCI directory %s. Skipping analysis of this image.", imageName)
			return createEmptyContainerResolution()
		}

		imageName = actualImageName
		imageTag = actualImageTag
	} else if strings.HasPrefix(strings.ToLower(imageName), ociArchivePrefix) {
		// This is an OCI archive tar file (created by buildah/skopeo) - extract from index.json
		log.Info().Msgf("Processing OCI archive tar file: %s", imageName)

		actualImageName, actualImageTag, err := extractImageNameAndTagFromOCIArchive(imageName)
		if err != nil {
			log.Warn().Err(err).Msgf("Failed to extract image name and tag from OCI archive %s. Skipping analysis of this file.", imageName)
			return createEmptyContainerResolution()
		}

		imageName = actualImageName
		imageTag = actualImageTag
		log.Info().Msgf("Extracted image name: %s, tag: %s from OCI archive", imageName, imageTag)
	} else if strings.HasSuffix(strings.ToLower(imageName), ".tar") {
		// This is a .tar file from docker/podman save - extract the actual image name and tag from manifest
		log.Info().Msgf("Processing Docker/Podman archive tar file: %s", imageName)

		// Try to extract the actual image name and tag from the tar file manifest
		actualImageName, actualImageTag, err := extractImageNameAndTagFromTar(imageName)
		if err != nil {
			log.Warn().Err(err).Msgf("Failed to extract image name and tag from Docker/Podman archive %s. Skipping analysis of this file.", imageName)
			return createEmptyContainerResolution()
		}

		// Use the actual image name and tag from the manifest
		imageName = actualImageName
		imageTag = actualImageTag
		log.Info().Msgf("Extracted image name: %s, tag: %s from Docker/Podman archive manifest", imageName, imageTag)
	} else if isCompressedTarFile(imageName) {
		// This is a compressed tar file - not supported by Syft
		log.Warn().Msgf("Compressed tar file detected: %s. Only uncompressed .tar files are supported. Please use 'save' command (like: 'docker save' or 'podman save') without compression or extract the file first. Skipping analysis of this file.", imageName)
		return createEmptyContainerResolution()
	} else {
		// Regular image name with potential tag
		var err error
		imageName, imageTag, err = parseImageNameAndTag(imageName)
		if err != nil {
			log.Warn().Err(err).Msgf("Skipping analysis of this image.")
			return createEmptyContainerResolution()
		}
	}

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

	extractImage(distro, imageModel, sourceMetadata, imageName, imageTag, &imageResult)
	extractImagePackages(s.Artifacts.Packages, distro, &imageResult)

	return imageResult
}

func extractImage(distro string, imageModel types.ImageModel, sourceMetadata source.ImageMetadata, imageName, imageTag string, result *ContainerResolution) {

	history := extractHistory(sourceMetadata)
	layerIds := extractLayerIds(history)

	// Create a consistent ImageId that represents the full image identifier, for regular images and for tar files
	imageId := fmt.Sprintf("%s:%s", imageName, imageTag)

	result.ContainerImage = ContainerImage{
		ImageName:      imageName,
		ImageTag:       imageTag,
		Distribution:   distro,
		ImageHash:      sourceMetadata.ID,
		ImageId:        imageId,
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
	return parseRpmSourceName(rpmMeta.SourceRpm)
}

func getRpmSourceVersion(pack pkg.Package, rpmMeta pkg.RpmDBEntry) string {
	if version := parseRpmSourceVersion(rpmMeta.SourceRpm); version != "" {
		return version
	}
	if rpmMeta.Version != "" {
		return rpmMeta.Version
	}
	return pack.Version
}

func parseRpmSourceName(sourceRpm string) string {
	if sourceRpm == "" {
		return ""
	}

	withoutSuffix := removeSrcRpmSuffix(sourceRpm)
	if withoutSuffix == "" {
		return ""
	}

	versionStartRegex := regexp.MustCompile(`-(\d+)`)
	versionStartMatch := versionStartRegex.FindStringIndex(withoutSuffix)
	if versionStartMatch != nil {
		versionStartIndex := versionStartMatch[0]
		return withoutSuffix[:versionStartIndex]
	}

	parts := strings.Split(withoutSuffix, "-")
	if len(parts) >= 3 {
		return strings.Join(parts[:len(parts)-2], "-")
	}
	return ""
}

func parseRpmSourceVersion(sourceRpm string) string {
	if sourceRpm == "" {
		return ""
	}

	withoutSuffix := removeSrcRpmSuffix(sourceRpm)
	if withoutSuffix == "" {
		return ""
	}

	versionStartRegex := regexp.MustCompile(`-(\d+)`)
	versionStartMatch := versionStartRegex.FindStringIndex(withoutSuffix)
	if versionStartMatch != nil {
		versionStartIndex := versionStartMatch[0] + 1
		return withoutSuffix[versionStartIndex:]
	}

	parts := strings.Split(withoutSuffix, "-")
	if len(parts) >= 3 {
		return strings.Join(parts[len(parts)-2:], "-")
	}
	return ""
}

func removeSrcRpmSuffix(sourceRpm string) string {
	suffix := ".src.rpm"
	sourceRpmLower := strings.ToLower(sourceRpm)
	suffixLower := strings.ToLower(suffix)

	if strings.HasSuffix(sourceRpmLower, suffixLower) {
		return sourceRpm[:len(sourceRpm)-len(suffix)]
	}
	return sourceRpm
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

// mapErrorToCustomMessage maps Syft library errors to user-friendly custom error messages
func mapErrorToCustomMessage(err error) string {
	if err == nil {
		return ""
	}

	errorStr := err.Error()
	errorLower := strings.ToLower(errorStr)

	// Check for each error pattern (case-insensitive)
	if strings.Contains(errorLower, "toomanyrequests") {
		return "Exceeded request limit to Docker Hub"
	}

	if strings.Contains(errorLower, "could not parse reference") {
		registry := extractRegistryFromError(errorStr)
		return fmt.Sprintf("Unable to parse image name or tag. %s", registry)
	}

	if strings.Contains(errorLower, "manifest_unknown") {
		registry := extractRegistryFromError(errorStr)
		return fmt.Sprintf("The requested image is not found or is unavailable. %s", registry)
	}

	if strings.Contains(errorLower, "authentication is required") {
		registry := extractRegistryFromError(errorStr)
		return fmt.Sprintf("Retrieval from the private repository failed. Verify the credentials used for the integration. %s", registry)
	}

	if strings.Contains(errorLower, "unauthorized") {
		registry := extractRegistryFromError(errorStr)
		return fmt.Sprintf("Access to the image is restricted. Verify the repository permissions and credentials. %s", registry)
	}

	if strings.Contains(errorLower, "no child with platform linux/amd64") {
		registry := extractRegistryFromError(errorStr)
		return fmt.Sprintf("The image is incompatible with the scanning tool. A Linux/AMD64 version is required. %s", registry)
	}

	if strings.Contains(errorLower, "unsupported mediatype") {
		registry := extractRegistryFromError(errorStr)
		return fmt.Sprintf("The image format is outdated and unsupported. You may need to update or rebuild the image. %s", registry)
	}

	// Default generic error message
	return "Unexpected error occurred during image resolution"
}

// extractRegistryFromError attempts to extract registry information from the error message
func extractRegistryFromError(errorStr string) string {
	// Try to extract registry URL patterns from the error
	// Common patterns: "https://registry.example.com/v2/", "registry.example.com", etc.

	// Pattern 1: Extract from URL format (https://registry.example.com/...)
	urlPattern := regexp.MustCompile(`https?://([^/\s:]+(?::\d+)?)`)
	if matches := urlPattern.FindStringSubmatch(errorStr); len(matches) > 1 {
		return fmt.Sprintf("Registry: %s", matches[1])
	}

	// Pattern 2: Extract from "Get \"https://...\"" format
	getPattern := regexp.MustCompile(`Get\s+"https?://([^/\s"]+)`)
	if matches := getPattern.FindStringSubmatch(errorStr); len(matches) > 1 {
		return fmt.Sprintf("Registry: %s", matches[1])
	}

	// Pattern 3: Extract from registry path format (registry.example.com/namespace/image)
	registryPattern := regexp.MustCompile(`([a-zA-Z0-9.-]+\.[a-zA-Z]{2,}(?::\d+)?)/`)
	if matches := registryPattern.FindStringSubmatch(errorStr); len(matches) > 1 {
		return fmt.Sprintf("Registry: %s", matches[1])
	}

	// If no registry found, return empty string
	return ""
}

// createUnresolvedResolution creates a ContainerResolution entry for an image that failed to resolve
func createUnresolvedResolution(imageModel types.ImageModel, err error) *ContainerResolution {
	imageNameAndTag := strings.Split(imageModel.Name, ":")
	imageName := imageNameAndTag[0]
	imageTag := ""
	if len(imageNameAndTag) > 1 {
		imageTag = imageNameAndTag[1]
	}

	// Map the error to a custom user-friendly message
	customErrorMessage := mapErrorToCustomMessage(err)

	return &ContainerResolution{
		ContainerImage: ContainerImage{
			ImageName:      imageName,
			ImageTag:       imageTag,
			Distribution:   types.NoFilePath,
			ImageHash:      "",
			ImageId:        imageModel.Name,
			Layers:         []string{},
			History:        []Layer{},
			ImageLocations: getImageLocations(imageModel.ImageLocations),
			Status:         "Failed",
			ScanError:      customErrorMessage,
		},
		ContainerPackages: []ContainerPackage{},
	}
}
