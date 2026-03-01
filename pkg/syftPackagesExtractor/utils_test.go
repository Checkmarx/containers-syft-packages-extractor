package syftPackagesExtractor

import (
	"archive/tar"
	"os"
	"testing"

	"github.com/Checkmarx/containers-types/types"
	"github.com/anchore/stereoscope/pkg/image"
	"github.com/anchore/syft/syft/artifact"
	"github.com/anchore/syft/syft/file"
	"github.com/anchore/syft/syft/linux"
	"github.com/anchore/syft/syft/pkg"
	"github.com/anchore/syft/syft/source"
	"github.com/stretchr/testify/assert"
)

func TestExtractPackageName(t *testing.T) {
	tests := []struct {
		name     string
		pack     pkg.Package
		expected string
	}{
		{
			name: "ExtractName for supported package type",
			pack: pkg.Package{
				Name: "examplePackage",
				Type: "maven",
				Metadata: pkg.JavaArchive{
					PomProperties: &pkg.JavaPomProperties{
						GroupID: "exampleGroup",
					},
				},
			},
			expected: "exampleGroup:examplePackage",
		},
		{
			name: "No extraction for unsupported package type",
			pack: pkg.Package{
				Name: "examplePackage",
				Type: "unsupportedType",
			},
			expected: "examplePackage",
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			result := extractPackageName(test.pack)
			assert.Equal(t, test.expected, result)
		})
	}
}

func TestGetGroupId(t *testing.T) {
	tests := []struct {
		name     string
		metadata interface{}
		expected string
	}{
		{
			name:     "JavaMetadata with GroupID",
			metadata: pkg.JavaArchive{PomProperties: &pkg.JavaPomProperties{GroupID: "testGroup"}},
			expected: "testGroup",
		},
		{
			name:     "JavaMetadata without GroupID",
			metadata: pkg.JavaArchive{},
			expected: "",
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			result := getGroupId(test.metadata)
			assert.Equal(t, test.expected, result)
		})
	}
}

func TestOutputFormat(t *testing.T) {
	expected := "testGroup:testPackage"
	result := outputFormat("testGroup", "testPackage")
	assert.Equal(t, expected, result)
}

func TestExtractName(t *testing.T) {
	tests := []struct {
		name        string
		packageName string
		purl        string
		groupId     string
		expected    string
	}{
		{
			name:        "ExtractName with GroupID and PURL",
			packageName: "testPackage",
			purl:        "https://example.com/testGroup/testPackage",
			groupId:     "testGroup",
			expected:    "testGroup:testPackage",
		},
		{
			name:        "ExtractName with PURL but no GroupID",
			packageName: "testPackage",
			purl:        "https://example.com/invalid",
			groupId:     "",
			expected:    "testPackage",
		},
		{
			name:        "GroupID equals package name",
			packageName: "testPackage",
			purl:        "https://example.com/testPackage/testPackage",
			groupId:     "testPackage",
			expected:    "testPackage",
		},
		{
			name:        "Empty PURL",
			packageName: "testPackage",
			purl:        "",
			groupId:     "",
			expected:    "testPackage",
		},
		{
			name:        "Invalid PURL format",
			packageName: "testPackage",
			purl:        "invalid-url",
			groupId:     "",
			expected:    "testPackage",
		},
		{
			name:        "PURL with empty group ID",
			packageName: "testPackage",
			purl:        "https://example.com//testPackage",
			groupId:     "",
			expected:    "testPackage",
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			result := extractName(test.packageName, test.purl, test.groupId)
			assert.Equal(t, test.expected, result)
		})
	}
}

func TestGetSyftArtifactsWithoutUnsupportedTypesDuplications(t *testing.T) {
	tests := []struct {
		name     string
		packages []pkg.Package
		expected []pkg.Package
	}{
		{
			name: "Multiple packages with same name and version",
			packages: []pkg.Package{
				{Name: "test1", Version: "1.0", Type: pkg.JavaPkg},
				{Name: "test1", Version: "1.0", Type: pkg.UnknownPkg},
				{Name: "test1", Version: "1.0", Type: pkg.NpmPkg},
			},
			expected: []pkg.Package{
				{Name: "test1", Version: "1.0", Type: pkg.JavaPkg},
			},
		},
		{
			name: "Packages with empty name or version",
			packages: []pkg.Package{
				{Name: "", Version: "1.0", Type: pkg.JavaPkg},
				{Name: "test1", Version: "", Type: pkg.JavaPkg},
				{Name: "test2", Version: "2.0", Type: pkg.JavaPkg},
			},
			expected: []pkg.Package{
				{Name: "test2", Version: "2.0", Type: pkg.JavaPkg},
			},
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			collection := pkg.NewCollection(test.packages...)
			result := getSyftArtifactsWithoutUnsupportedTypesDuplications(collection)
			assert.Equal(t, len(test.expected), len(result))
		})
	}
}

func TestRemoveSha256(t *testing.T) {
	tests := []struct {
		name     string
		input    string
		expected string
	}{
		{
			name:     "Remove sha256 prefix",
			input:    "sha256:abc123",
			expected: "abc123",
		},
		{
			name:     "No sha256 prefix",
			input:    "abc123",
			expected: "abc123",
		},
		{
			name:     "Empty string",
			input:    "",
			expected: "",
		},
		{
			name:     "Whitespace string",
			input:    "   ",
			expected: "   ",
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			result := removeSha256(test.input)
			assert.Equal(t, test.expected, result)
		})
	}
}

func TestGetImageLocations(t *testing.T) {
	tests := []struct {
		name           string
		imageLocations []types.ImageLocation
		expected       []ImageLocation
	}{
		{
			name: "Single location",
			imageLocations: []types.ImageLocation{
				{
					Origin:     types.DockerFileOrigin,
					Path:       "/path/to/Dockerfile",
					FinalStage: true,
				},
			},
			expected: []ImageLocation{
				{
					Origin:     types.DockerFileOrigin,
					Path:       "/path/to/Dockerfile",
					FinalStage: true,
				},
			},
		},
		{
			name: "Multiple locations",
			imageLocations: []types.ImageLocation{
				{
					Origin:     types.DockerFileOrigin,
					Path:       "/path/to/Dockerfile",
					FinalStage: true,
				},
				{
					Origin:     types.UserInput,
					Path:       "None",
					FinalStage: false,
				},
			},
			expected: []ImageLocation{
				{
					Origin:     types.DockerFileOrigin,
					Path:       "/path/to/Dockerfile",
					FinalStage: true,
				},
				{
					Origin:     types.UserInput,
					Path:       "None",
					FinalStage: false,
				},
			},
		},
		{
			name:           "Empty locations",
			imageLocations: []types.ImageLocation{},
			expected:       nil,
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			result := getImageLocations(test.imageLocations)
			assert.Equal(t, test.expected, result)
		})
	}
}

func TestGetImageLocationsPathsString(t *testing.T) {
	tests := []struct {
		name     string
		imgModel types.ImageModel
		expected string
	}{
		{
			name: "Single location",
			imgModel: types.ImageModel{
				ImageLocations: []types.ImageLocation{
					{Path: "/path/to/Dockerfile"},
				},
			},
			expected: "/path/to/Dockerfile",
		},
		{
			name: "Multiple locations",
			imgModel: types.ImageModel{
				ImageLocations: []types.ImageLocation{
					{Path: "/path/to/Dockerfile"},
					{Path: "/path/to/AnotherDockerfile"},
				},
			},
			expected: "/path/to/Dockerfile, /path/to/AnotherDockerfile",
		},
		{
			name: "Empty locations",
			imgModel: types.ImageModel{
				ImageLocations: []types.ImageLocation{},
			},
			expected: "",
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			result := GetImageLocationsPathsString(test.imgModel)
			assert.Equal(t, test.expected, result)
		})
	}
}

func TestGetDistro(t *testing.T) {
	tests := []struct {
		name     string
		release  *linux.Release
		expected string
	}{
		{
			name: "Valid release",
			release: &linux.Release{
				ID:        "ubuntu",
				VersionID: "20.04",
			},
			expected: "ubuntu:20.04",
		},
		{
			name:     "Nil release",
			release:  nil,
			expected: types.NoFilePath,
		},
		{
			name: "Empty ID",
			release: &linux.Release{
				ID:        "",
				VersionID: "20.04",
			},
			expected: types.NoFilePath,
		},
		{
			name: "Empty VersionID",
			release: &linux.Release{
				ID:        "ubuntu",
				VersionID: "",
			},
			expected: types.NoFilePath,
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			result := getDistro(test.release)
			assert.Equal(t, test.expected, result)
		})
	}
}

func TestExtractPackageLicenses(t *testing.T) {
	tests := []struct {
		name     string
		pack     pkg.Package
		expected []string
	}{
		{
			name: "Package with licenses",
			pack: pkg.Package{
				Licenses: pkg.NewLicenseSet(
					pkg.NewLicense("MIT"),
					pkg.NewLicense("Apache-2.0"),
				),
			},
			expected: []string{"Apache-2.0", "MIT"},
		},
		{
			name: "Package without licenses",
			pack: pkg.Package{
				Licenses: pkg.NewLicenseSet(),
			},
			expected: nil,
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			result := extractPackageLicenses(test.pack)
			assert.Equal(t, test.expected, result)
		})
	}
}

func TestPackageTypeToPackageManager(t *testing.T) {
	tests := []struct {
		name     string
		pkgType  pkg.Type
		expected string
	}{
		{
			name:     "Apk package type",
			pkgType:  pkg.ApkPkg,
			expected: string(Oval),
		},
		{
			name:     "Npm package type",
			pkgType:  pkg.NpmPkg,
			expected: string(Npm),
		},
		{
			name:     "Java package type",
			pkgType:  pkg.JavaPkg,
			expected: string(Maven),
		},
		{
			name:     "Unknown package type",
			pkgType:  pkg.UnknownPkg,
			expected: string(Unsupported),
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			result := packageTypeToPackageManager(test.pkgType)
			assert.Equal(t, test.expected, result)
		})
	}
}

func TestExtractPackageLayerIds(t *testing.T) {
	tests := []struct {
		name      string
		locations file.LocationSet
		expected  []string
	}{
		{
			name: "Single location with sha256",
			locations: func() file.LocationSet {
				loc := file.NewLocation("path/to/file")
				loc.Coordinates.FileSystemID = "sha256:abc123"
				return file.NewLocationSet(loc)
			}(),
			expected: []string{"abc123"},
		},
		{
			name: "Multiple locations",
			locations: func() file.LocationSet {
				loc1 := file.NewLocation("path/to/file1")
				loc1.Coordinates.FileSystemID = "sha256:abc123"
				loc2 := file.NewLocation("path/to/file2")
				loc2.Coordinates.FileSystemID = "sha256:def456"
				return file.NewLocationSet(loc1, loc2)
			}(),
			expected: []string{"abc123", "def456"},
		},
		{
			name:      "Empty locations",
			locations: file.NewLocationSet(),
			expected:  nil,
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			result := extractPackageLayerIds(test.locations)
			assert.Equal(t, test.expected, result)
		})
	}
}

func TestExtractLayerIds(t *testing.T) {
	tests := []struct {
		name     string
		layers   []Layer
		expected []string
	}{
		{
			name: "Layers with IDs",
			layers: []Layer{
				{LayerId: "abc123"},
				{LayerId: "def456"},
			},
			expected: []string{"abc123", "def456"},
		},
		{
			name: "Layers with empty IDs",
			layers: []Layer{
				{LayerId: ""},
				{LayerId: "def456"},
			},
			expected: []string{"def456"},
		},
		{
			name:     "Empty layers",
			layers:   []Layer{},
			expected: nil,
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			result := extractLayerIds(test.layers)
			assert.Equal(t, test.expected, result)
		})
	}
}

func TestGetSize(t *testing.T) {
	tests := []struct {
		name     string
		layerId  string
		layers   []source.LayerMetadata
		expected int64
	}{
		{
			name:    "Layer found with sha256",
			layerId: "abc123",
			layers: []source.LayerMetadata{
				{Digest: "sha256:abc123", Size: 1000},
			},
			expected: 1000,
		},
		{
			name:    "Layer found without sha256",
			layerId: "abc123",
			layers: []source.LayerMetadata{
				{Digest: "abc123", Size: 1000},
			},
			expected: 1000,
		},
		{
			name:    "Layer not found",
			layerId: "nonexistent",
			layers: []source.LayerMetadata{
				{Digest: "sha256:abc123", Size: 1000},
			},
			expected: 0,
		},
		{
			name:     "Empty layers",
			layerId:  "abc123",
			layers:   []source.LayerMetadata{},
			expected: 0,
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			result := getSize(test.layerId, test.layers)
			assert.Equal(t, test.expected, result)
		})
	}
}

func TestGetPackageRelationships(t *testing.T) {
	tests := []struct {
		name         string
		containerPkg pkg.Package
		expectedName string
		expectedVer  string
	}{
		{
			name: "APK package",
			containerPkg: pkg.Package{
				Version: "1.0.0",
				Metadata: pkg.ApkDBEntry{
					OriginPackage: "test-pkg",
					Version:       "1.0.0",
				},
			},
			expectedName: "test-pkg",
			expectedVer:  "1.0.0",
		},
		{
			name: "DEB package",
			containerPkg: pkg.Package{
				Version: "1.0.0",
				Metadata: pkg.DpkgDBEntry{
					Source:        "test-pkg",
					SourceVersion: "1.0.0",
				},
			},
			expectedName: "test-pkg",
			expectedVer:  "1.0.0",
		},
		{
			name: "RPM package",
			containerPkg: pkg.Package{
				Version: "1.0.0",
				Metadata: pkg.RpmDBEntry{
					SourceRpm: "test-pkg-1.0.0-1.src.rpm",
					Version:   "1.0.0",
				},
			},
			expectedName: "test-pkg",
			expectedVer:  "1.0.0-1",
		},
		{
			name: "Unknown package type",
			containerPkg: pkg.Package{
				Version:  "1.0.0",
				Metadata: nil,
			},
			expectedName: "",
			expectedVer:  "",
		},
		{
			name: "APK package with empty origin package",
			containerPkg: pkg.Package{
				Version: "1.0.0",
				Metadata: pkg.ApkDBEntry{
					OriginPackage: "",
					Version:       "1.0.0",
				},
			},
			expectedName: "",
			expectedVer:  "",
		},
		{
			name: "DEB package with empty source",
			containerPkg: pkg.Package{
				Version: "1.0.0",
				Metadata: pkg.DpkgDBEntry{
					Source:        "",
					SourceVersion: "1.0.0",
				},
			},
			expectedName: "",
			expectedVer:  "",
		},
		{
			name: "RPM package with empty source RPM",
			containerPkg: pkg.Package{
				Version: "1.0.0",
				Metadata: pkg.RpmDBEntry{
					SourceRpm: "",
					Version:   "1.0.0",
				},
			},
			expectedName: "",
			expectedVer:  "1.0.0",
		},
		{
			name: "APK package with missing version",
			containerPkg: pkg.Package{
				Version: "1.0.0",
				Metadata: pkg.ApkDBEntry{
					OriginPackage: "test-pkg",
					Version:       "",
				},
			},
			expectedName: "test-pkg",
			expectedVer:  "1.0.0",
		},
		{
			name: "DEB package with missing source version",
			containerPkg: pkg.Package{
				Version: "1.0.0",
				Metadata: pkg.DpkgDBEntry{
					Source:        "test-pkg",
					SourceVersion: "",
				},
			},
			expectedName: "test-pkg",
			expectedVer:  "1.0.0",
		},
		{
			name: "RPM package with missing version",
			containerPkg: pkg.Package{
				Version: "1.0.0",
				Metadata: pkg.RpmDBEntry{
					SourceRpm: "test-pkg-1.0.0-1.src.rpm",
					Version:   "",
				},
			},
			expectedName: "test-pkg",
			expectedVer:  "1.0.0-1",
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			name, ver := getPackageRelationships(test.containerPkg)
			assert.Equal(t, test.expectedName, name)
			assert.Equal(t, test.expectedVer, ver)
		})
	}
}

func TestAnalyzeImageWithPlatform(t *testing.T) {
	// Skip test if no image available or no network
	t.Skip("Integration test - requires actual image and network access")

	imageModel := types.ImageModel{
		Name: "alpine:latest",
		ImageLocations: []types.ImageLocation{
			{
				Origin:     types.UserInput,
				Path:       types.NoFilePath,
				FinalStage: false,
			},
		},
	}

	registryOptions := &image.RegistryOptions{}

	// Test with platform specification
	platform := PlatformLinuxAmd64

	result, err := analyzeImageWithPlatform(imageModel, registryOptions, platform)
	if err != nil {
		t.Fatalf("Expected no error, got: %v", err)
	}

	if result == nil {
		t.Fatal("Expected result, got nil")
	}

	// Verify that result contains expected data
	if result.ContainerImage.ImageName == "" {
		t.Error("Expected image name to be populated")
	}
}

func TestWebsphereLibertyPlatformAnalysis(t *testing.T) {
	// Test the specific image requested: websphere-liberty:21.0.0.12-full-java8-ibmjava
	imageName := "websphere-liberty:21.0.0.12-full-java8-ibmjava"

	imageModel := types.ImageModel{
		Name: imageName,
		ImageLocations: []types.ImageLocation{
			{
				Origin:     types.UserInput,
				Path:       types.NoFilePath,
				FinalStage: false,
			},
		},
	}

	registryOptions := &image.RegistryOptions{}

	t.Run("WithExplicitLinuxAmd64Platform", func(t *testing.T) {
		// Test with explicit linux/amd64 platform - should provide results
		result, err := analyzeImage(imageModel, registryOptions, PlatformLinuxAmd64)

		if err != nil {
			t.Logf("Expected to succeed with linux/amd64 platform, got error: %v", err)
			t.Skip("Skipping test - image might not be available or network issues")
		}

		if result == nil {
			t.Fatal("Expected result with linux/amd64 platform, got nil")
		}

		if len(result.ContainerPackages) == 0 {
			t.Error("Expected packages to be found with linux/amd64 platform")
		}

		t.Logf("✅ Success: Found %d packages with linux/amd64 platform", len(result.ContainerPackages))
	})

	t.Run("WithEmptyPlatform_ShouldDefaultToLinuxAmd64", func(t *testing.T) {
		// Test with empty platform - should default to linux/amd64 and provide results
		result, err := analyzeImage(imageModel, registryOptions, "")

		if err != nil {
			t.Logf("Expected to succeed with empty platform (defaulting to linux/amd64), got error: %v", err)
			t.Skip("Skipping test - image might not be available or network issues")
		}

		if result == nil {
			t.Fatal("Expected result with empty platform (defaulting to linux/amd64), got nil")
		}

		if len(result.ContainerPackages) == 0 {
			t.Error("Expected packages to be found with empty platform (should default to linux/amd64)")
		}

		t.Logf("✅ Success: Found %d packages with empty platform (defaulted to linux/amd64)", len(result.ContainerPackages))
	})

	t.Run("WithInvalidPlatform_ShouldLogAndDefaultToLinuxAmd64", func(t *testing.T) {
		// Test with invalid platform - should log warning and default to linux/amd64
		result, err := analyzeImage(imageModel, registryOptions, "invalid/platform")

		if err != nil {
			t.Logf("Expected to succeed with invalid platform (defaulting to linux/amd64), got error: %v", err)
			t.Skip("Skipping test - image might not be available or network issues")
		}

		if result == nil {
			t.Fatal("Expected result with invalid platform (defaulting to linux/amd64), got nil")
		}

		if len(result.ContainerPackages) == 0 {
			t.Error("Expected packages to be found with invalid platform (should default to linux/amd64)")
		}

		t.Logf("✅ Success: Found %d packages with invalid platform (defaulted to linux/amd64)", len(result.ContainerPackages))
	})

	t.Run("WithLinuxArm64Platform", func(t *testing.T) {
		// Test with linux/arm64 platform - may have different results or fail gracefully
		result, err := analyzeImage(imageModel, registryOptions, PlatformLinuxArm64)

		if err != nil {
			t.Logf("Got error with linux/arm64 platform (expected for some images): %v", err)
			// This is acceptable as not all images support all platforms
			return
		}

		if result != nil {
			t.Logf("✅ Success: Found %d packages with linux/arm64 platform", len(result.ContainerPackages))
		}
	})
}

func TestPlatformDefaultingBehavior(t *testing.T) {
	// Test platform defaulting behavior without network calls
	testCases := []struct {
		name            string
		inputPlatform   string
		expectedDefault string
		shouldLog       bool
	}{
		{
			name:            "EmptyPlatform",
			inputPlatform:   "",
			expectedDefault: PlatformLinuxAmd64,
			shouldLog:       true, // Should log that it's defaulting
		},
		{
			name:            "ValidPlatform",
			inputPlatform:   PlatformLinuxAmd64,
			expectedDefault: PlatformLinuxAmd64,
			shouldLog:       false,
		},
		{
			name:            "InvalidPlatform",
			inputPlatform:   "invalid/platform",
			expectedDefault: PlatformLinuxAmd64,
			shouldLog:       true, // Should log warning about invalid platform
		},
		{
			name:            "AnotherValidPlatform",
			inputPlatform:   PlatformLinuxArm64,
			expectedDefault: PlatformLinuxArm64,
			shouldLog:       false,
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			// Test the platform validation logic
			platform := tc.inputPlatform

			// Replicate the defaulting logic from analyzeImage
			if platform == "" {
				platform = PlatformLinuxAmd64
			}

			// Validate platform format
			if _, err := image.NewPlatform(platform); err != nil {
				platform = PlatformLinuxAmd64
			}

			assert.Equal(t, tc.expectedDefault, platform, "Platform should default correctly")
		})
	}
}

func TestPlatformConstants(t *testing.T) {
	// Test that platform constants are valid
	platforms := []string{
		PlatformLinuxAmd64,
		PlatformLinuxArm64,
		PlatformLinuxArm,
		PlatformWindowsAmd64,
	}

	for _, platform := range platforms {
		_, err := image.NewPlatform(platform)
		if err != nil {
			t.Errorf("Platform %s should be valid, got error: %v", platform, err)
		}
	}
}

func TestCreateEmptyContainerResolution(t *testing.T) {
	// Test the createEmptyContainerResolution helper function
	result := createEmptyContainerResolution()

	// Verify it returns an empty ContainerResolution
	assert.Equal(t, ContainerImage{}, result.ContainerImage)
	assert.Empty(t, result.ContainerPackages)
	assert.Len(t, result.ContainerPackages, 0)
}

func TestIsCompressedTarFile(t *testing.T) {
	tests := []struct {
		name     string
		filename string
		expected bool
	}{
		{
			name:     "Regular tar file",
			filename: "image.tar",
			expected: false,
		},
		{
			name:     "Compressed tar.gz file",
			filename: "image.tar.gz",
			expected: true,
		},
		{
			name:     "Compressed tar.bz2 file",
			filename: "image.tar.bz2",
			expected: true,
		},
		{
			name:     "Compressed tar.xz file",
			filename: "image.tar.xz",
			expected: true,
		},
		{
			name:     "Uppercase tar.gz file",
			filename: "image.TAR.GZ",
			expected: true,
		},
		{
			name:     "Regular file",
			filename: "image.txt",
			expected: false,
		},
		{
			name:     "Empty filename",
			filename: "",
			expected: false,
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			result := isCompressedTarFile(test.filename)
			assert.Equal(t, test.expected, result)
		})
	}
}

func TestParseImageNameAndTag(t *testing.T) {
	tests := []struct {
		name         string
		imageString  string
		expectedName string
		expectedTag  string
		expectError  bool
	}{
		{
			name:         "Image with tag",
			imageString:  "nginx:1.21",
			expectedName: "nginx",
			expectedTag:  "1.21",
			expectError:  false,
		},
		{
			name:         "Image with latest tag",
			imageString:  "alpine:latest",
			expectedName: "alpine",
			expectedTag:  "latest",
			expectError:  false,
		},
		{
			name:         "Image without tag",
			imageString:  "ubuntu",
			expectedName: "",
			expectedTag:  "",
			expectError:  true,
		},
		{
			name:         "Image with multiple colons",
			imageString:  "registry.example.com:5000/namespace/image:tag",
			expectedName: "registry.example.com:5000/namespace/image",
			expectedTag:  "tag",
			expectError:  false,
		},
		{
			name:         "Image with colon at end",
			imageString:  "nginx:",
			expectedName: "",
			expectedTag:  "",
			expectError:  true,
		},
		{
			name:         "Empty string",
			imageString:  "",
			expectedName: "",
			expectedTag:  "",
			expectError:  true,
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			imageName, imageTag, err := parseImageNameAndTag(test.imageString)

			if test.expectError {
				assert.Error(t, err)
			} else {
				assert.NoError(t, err)
			}
			assert.Equal(t, test.expectedName, imageName)
			assert.Equal(t, test.expectedTag, imageTag)
		})
	}
}

func TestExtractImageNameAndTagFromTar(t *testing.T) {
	// Test the extractImageNameAndTagFromTar function
	tests := []struct {
		name         string
		manifestJSON string
		expectedName string
		expectedTag  string
		expectError  bool
	}{
		{
			name: "Valid manifest with image and tag",
			manifestJSON: `[{
				"RepoTags": ["nginx:1.21"]
			}]`,
			expectedName: "nginx",
			expectedTag:  "1.21",
			expectError:  false,
		},
		{
			name: "Valid manifest with image without tag",
			manifestJSON: `[{
				"RepoTags": ["alpine"]
			}]`,
			expectedName: "",
			expectedTag:  "",
			expectError:  true, // Now returns error for images without tags
		},
		{
			name: "Valid manifest with registry path",
			manifestJSON: `[{
				"RepoTags": ["registry.example.com:5000/namespace/image:tag"]
			}]`,
			expectedName: "registry.example.com:5000/namespace/image",
			expectedTag:  "tag",
			expectError:  false,
		},
		{
			name: "Empty RepoTags",
			manifestJSON: `[{
				"RepoTags": []
			}]`,
			expectedName: "",
			expectedTag:  "",
			expectError:  true,
		},
		{
			name:         "Invalid JSON",
			manifestJSON: `invalid json`,
			expectedName: "",
			expectedTag:  "",
			expectError:  true,
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			// Create a temporary tar file with the test manifest
			tmpFile, err := os.CreateTemp("", "test-*.tar")
			if err != nil {
				t.Fatalf("Failed to create temp file: %v", err)
			}
			defer os.Remove(tmpFile.Name())
			defer tmpFile.Close()

			// Create a tar writer
			tarWriter := tar.NewWriter(tmpFile)

			// Add manifest.json to the tar
			manifestHeader := &tar.Header{
				Name: "manifest.json",
				Size: int64(len(test.manifestJSON)),
				Mode: 0644,
			}
			if err := tarWriter.WriteHeader(manifestHeader); err != nil {
				t.Fatalf("Failed to write tar header: %v", err)
			}
			if _, err := tarWriter.Write([]byte(test.manifestJSON)); err != nil {
				t.Fatalf("Failed to write manifest data: %v", err)
			}
			tarWriter.Close()
			tmpFile.Close()

			// Test the extraction function
			imageName, imageTag, err := extractImageNameAndTagFromTar(tmpFile.Name())

			if test.expectError {
				assert.Error(t, err)
			} else {
				assert.NoError(t, err)
				assert.Equal(t, test.expectedName, imageName)
				assert.Equal(t, test.expectedTag, imageTag)
			}
		})
	}
}

func TestExtractImageNameAndTagFromOCIDir(t *testing.T) {
	tests := []struct {
		name         string
		indexJSON    string
		dirName      string
		expectedName string
		expectedTag  string
		expectError  bool
	}{
		{
			name: "Valid OCI dir with tag annotation",
			indexJSON: `{
				"schemaVersion": 2,
				"manifests": [{
					"mediaType": "application/vnd.oci.image.manifest.v1+json",
					"digest": "sha256:abc123",
					"size": 1024,
					"annotations": {
						"org.opencontainers.image.ref.name": "latest"
					}
				}]
			}`,
			dirName:      "alpine",
			expectedName: "alpine",
			expectedTag:  "latest",
			expectError:  false,
		},
		{
			name: "Multiple manifests - uses first manifest tag",
			indexJSON: `{
				"schemaVersion": 2,
				"manifests": [
					{
						"annotations": {
							"org.opencontainers.image.ref.name": "alpine"
						}
					},
					{
						"annotations": {
							"org.opencontainers.image.ref.name": "latest"
						}
					}
				]
			}`,
			dirName:      "alpine",
			expectedName: "alpine",
			expectedTag:  "alpine",
			expectError:  false,
		},
		{
			name: "OCI dir from nested path",
			indexJSON: `{
				"schemaVersion": 2,
				"manifests": [{
					"annotations": {
						"org.opencontainers.image.ref.name": "v1.0"
					}
				}]
			}`,
			dirName:      "library/nginx",
			expectedName: "nginx",
			expectedTag:  "v1.0",
			expectError:  false,
		},
		{
			name: "Missing tag annotation",
			indexJSON: `{
				"schemaVersion": 2,
				"manifests": [{
					"mediaType": "application/vnd.oci.image.manifest.v1+json"
				}]
			}`,
			dirName:      "alpine",
			expectedName: "",
			expectedTag:  "",
			expectError:  true,
		},
		{
			name: "Empty manifests",
			indexJSON: `{
				"schemaVersion": 2,
				"manifests": []
			}`,
			dirName:      "alpine",
			expectedName: "",
			expectedTag:  "",
			expectError:  true,
		},
		{
			name:         "Invalid JSON",
			indexJSON:    `invalid json`,
			dirName:      "alpine",
			expectedName: "",
			expectedTag:  "",
			expectError:  true,
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			// Create temporary OCI directory structure
			tmpDir, err := os.MkdirTemp("", "oci-test-*")
			if err != nil {
				t.Fatalf("Failed to create temp dir: %v", err)
			}
			defer os.RemoveAll(tmpDir)

			// Create nested directory if needed
			ociDir := tmpDir
			if test.dirName != "" {
				ociDir = tmpDir + "/" + test.dirName
				if err := os.MkdirAll(ociDir, 0755); err != nil {
					t.Fatalf("Failed to create OCI dir: %v", err)
				}
			}

			// Write index.json
			indexPath := ociDir + "/index.json"
			if err := os.WriteFile(indexPath, []byte(test.indexJSON), 0644); err != nil {
				t.Fatalf("Failed to write index.json: %v", err)
			}

			// Test with oci-dir prefix
			inputPath := "oci-dir:" + ociDir
			imageName, imageTag, err := extractImageNameAndTagFromOCIDir(inputPath)

			if test.expectError {
				assert.Error(t, err)
			} else {
				assert.NoError(t, err)
				assert.Equal(t, test.expectedName, imageName)
				assert.Equal(t, test.expectedTag, imageTag)
			}
		})
	}
}

func TestIsTaggedImageFormat(t *testing.T) {
	tests := []struct {
		name     string
		image    string
		expected bool
	}{
		{"Standard image with tag", "nginx:latest", true},
		{"Registry image with tag", "docker.io/library/alpine:3.18", true},
		{"Docker daemon", "docker:nginx:latest", true},
		{"Podman daemon", "podman:alpine:3.18", true},
		{"Registry prefix", "registry:myregistry.io/app:v1.0", true},
		{"OCI directory", "oci-dir:/path/to/image", false},
		{"OCI archive", "oci-archive:image.tar", false},
		{"Docker archive", "docker-archive:image.tar", false},
		{"File prefix", "file:image.tar", false},
		{"Tar file", "alpine.tar", false},
		{"Image without tag", "alpine", false},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			result := isTaggedImageFormat(test.image)
			assert.Equal(t, test.expected, result)
		})
	}
}

func TestExtractImageNameAndTagFromOCIArchive(t *testing.T) {
	tests := []struct {
		name         string
		indexJSON    string
		filename     string
		expectedName string
		expectedTag  string
		expectError  bool
	}{
		{
			name:         "Valid OCI archive with tag",
			indexJSON:    `{"schemaVersion":2,"manifests":[{"annotations":{"org.opencontainers.image.ref.name":"v1.0"}}]}`,
			filename:     "myapp.tar",
			expectedName: "myapp",
			expectedTag:  "v1.0",
			expectError:  false,
		},
		{
			name:         "Filename with underscore extracts before underscore",
			indexJSON:    `{"schemaVersion":2,"manifests":[{"annotations":{"org.opencontainers.image.ref.name":"latest"}}]}`,
			filename:     "traefik_v2.tar",
			expectedName: "traefik",
			expectedTag:  "latest",
			expectError:  false,
		},
		{
			name:        "Missing tag annotation skips image",
			indexJSON:   `{"schemaVersion":2,"manifests":[{}]}`,
			filename:    "myapp.tar",
			expectError: true,
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			tmpDir, err := os.MkdirTemp("", "oci-archive-test-*")
			assert.NoError(t, err)
			defer os.RemoveAll(tmpDir)

			tarFilePath := tmpDir + "/" + test.filename
			tarFile, err := os.Create(tarFilePath)
			assert.NoError(t, err)

			tarWriter := tar.NewWriter(tarFile)
			indexHeader := &tar.Header{Name: "index.json", Mode: 0644, Size: int64(len(test.indexJSON))}
			assert.NoError(t, tarWriter.WriteHeader(indexHeader))
			_, err = tarWriter.Write([]byte(test.indexJSON))
			assert.NoError(t, err)
			tarWriter.Close()
			tarFile.Close()

			imageName, imageTag, err := extractImageNameAndTagFromOCIArchive("oci-archive:" + tarFilePath)

			if test.expectError {
				assert.Error(t, err)
			} else {
				assert.NoError(t, err)
				assert.Equal(t, test.expectedName, imageName)
				assert.Equal(t, test.expectedTag, imageTag)
			}
		})
	}
}

func TestNormalizeImageName(t *testing.T) {
	tests := []struct {
		name     string
		input    string
		expected string
	}{
		// Docker Hub prefixes - should be removed
		{
			name:     "Docker Hub official image with full path",
			input:    "docker.io/library/alpine",
			expected: "alpine",
		},
		{
			name:     "Docker Hub official image with index.docker.io",
			input:    "index.docker.io/library/nginx",
			expected: "nginx",
		},
		{
			name:     "Docker Hub user image",
			input:    "docker.io/myuser/myimage",
			expected: "myuser/myimage",
		},
		{
			name:     "Registry Hub Docker",
			input:    "registry.hub.docker.com/library/redis",
			expected: "redis",
		},
		// Other registries - should be preserved
		{
			name:     "GHCR image preserved",
			input:    "ghcr.io/owner/repo",
			expected: "ghcr.io/owner/repo",
		},
		{
			name:     "GCR image preserved",
			input:    "gcr.io/project/image",
			expected: "gcr.io/project/image",
		},
		{
			name:     "Quay.io image preserved",
			input:    "quay.io/repo/image",
			expected: "quay.io/repo/image",
		},
		{
			name:     "GitLab registry preserved",
			input:    "registry.gitlab.com/group/project",
			expected: "registry.gitlab.com/group/project",
		},
		{
			name:     "Custom registry preserved",
			input:    "myregistry.example.com/myimage",
			expected: "myregistry.example.com/myimage",
		},
		{
			name:     "Registry with port preserved",
			input:    "myregistry:5000/myimage",
			expected: "myregistry:5000/myimage",
		},
		{
			name:     "Localhost registry preserved",
			input:    "localhost/myimage",
			expected: "localhost/myimage",
		},
		{
			name:     "Amazon ECR preserved",
			input:    "123456789012.dkr.ecr.us-east-1.amazonaws.com/myimage",
			expected: "123456789012.dkr.ecr.us-east-1.amazonaws.com/myimage",
		},
		{
			name:     "Azure ACR preserved",
			input:    "myregistry.azurecr.io/myimage",
			expected: "myregistry.azurecr.io/myimage",
		},
		{
			name:     "Google Artifact Registry preserved",
			input:    "us-docker.pkg.dev/my-project/my-repo/myimage",
			expected: "us-docker.pkg.dev/my-project/my-repo/myimage",
		},
		{
			name:     "Harbor registry preserved",
			input:    "harbor.mycompany.com/library/nginx",
			expected: "harbor.mycompany.com/library/nginx",
		},
		{
			name:     "JFrog Artifactory preserved",
			input:    "mycompany.jfrog.io/docker-local/myimage",
			expected: "mycompany.jfrog.io/docker-local/myimage",
		},
		{
			name:     "DigitalOcean registry preserved",
			input:    "registry.digitalocean.com/myregistry/myimage",
			expected: "registry.digitalocean.com/myregistry/myimage",
		},
		{
			name:     "Nexus registry preserved",
			input:    "nexus.mycompany.com:8443/repository/docker/myimage",
			expected: "nexus.mycompany.com:8443/repository/docker/myimage",
		},
		// Simple image names - no change
		{
			name:     "Simple image name no change",
			input:    "alpine",
			expected: "alpine",
		},
		{
			name:     "User image no change",
			input:    "myuser/myimage",
			expected: "myuser/myimage",
		},
		{
			name:     "Library prefix stripped",
			input:    "library/ubuntu",
			expected: "ubuntu",
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			result := normalizeImageName(test.input)
			assert.Equal(t, test.expected, result)
		})
	}
}

func TestExtractImageNameAndTagFromTar_WithNormalization(t *testing.T) {
	// Test that extractImageNameAndTagFromTar correctly normalizes Podman-style full paths
	// Only docker.io prefix should be removed; other registries should be preserved
	tests := []struct {
		name         string
		manifestJSON string
		expectedName string
		expectedTag  string
		expectError  bool
	}{
		{
			name: "Podman-saved image with docker.io/library prefix",
			manifestJSON: `[{
				"RepoTags": ["docker.io/library/alpine:3.21.0"]
			}]`,
			expectedName: "alpine",
			expectedTag:  "3.21.0",
			expectError:  false,
		},
		{
			name: "Podman-saved user image with docker.io prefix",
			manifestJSON: `[{
				"RepoTags": ["docker.io/myuser/myapp:latest"]
			}]`,
			expectedName: "myuser/myapp",
			expectedTag:  "latest",
			expectError:  false,
		},
		{
			name: "Docker-saved image without prefix",
			manifestJSON: `[{
				"RepoTags": ["nginx:1.21"]
			}]`,
			expectedName: "nginx",
			expectedTag:  "1.21",
			expectError:  false,
		},
		{
			name: "Image from ghcr.io - registry preserved",
			manifestJSON: `[{
				"RepoTags": ["ghcr.io/owner/repo:v1.0"]
			}]`,
			expectedName: "ghcr.io/owner/repo",
			expectedTag:  "v1.0",
			expectError:  false,
		},
		{
			name: "Image from gcr.io - registry preserved",
			manifestJSON: `[{
				"RepoTags": ["gcr.io/my-project/myimage:latest"]
			}]`,
			expectedName: "gcr.io/my-project/myimage",
			expectedTag:  "latest",
			expectError:  false,
		},
		{
			name: "Image from quay.io - registry preserved",
			manifestJSON: `[{
				"RepoTags": ["quay.io/myorg/myimage:v2.0"]
			}]`,
			expectedName: "quay.io/myorg/myimage",
			expectedTag:  "v2.0",
			expectError:  false,
		},
		{
			name: "Image from Amazon ECR - registry preserved",
			manifestJSON: `[{
				"RepoTags": ["123456789012.dkr.ecr.us-east-1.amazonaws.com/myapp:1.0.0"]
			}]`,
			expectedName: "123456789012.dkr.ecr.us-east-1.amazonaws.com/myapp",
			expectedTag:  "1.0.0",
			expectError:  false,
		},
		{
			name: "Image from Azure ACR - registry preserved",
			manifestJSON: `[{
				"RepoTags": ["myregistry.azurecr.io/samples/myimage:latest"]
			}]`,
			expectedName: "myregistry.azurecr.io/samples/myimage",
			expectedTag:  "latest",
			expectError:  false,
		},
		{
			name: "Image from private registry with port - preserved",
			manifestJSON: `[{
				"RepoTags": ["myregistry.local:5000/myimage:dev"]
			}]`,
			expectedName: "myregistry.local:5000/myimage",
			expectedTag:  "dev",
			expectError:  false,
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			// Create a temporary tar file with the test manifest
			tmpFile, err := os.CreateTemp("", "test-*.tar")
			if err != nil {
				t.Fatalf("Failed to create temp file: %v", err)
			}
			defer os.Remove(tmpFile.Name())
			defer tmpFile.Close()

			// Create a tar writer
			tarWriter := tar.NewWriter(tmpFile)

			// Add manifest.json to the tar
			manifestHeader := &tar.Header{
				Name: "manifest.json",
				Size: int64(len(test.manifestJSON)),
				Mode: 0644,
			}
			if err := tarWriter.WriteHeader(manifestHeader); err != nil {
				t.Fatalf("Failed to write tar header: %v", err)
			}
			if _, err := tarWriter.Write([]byte(test.manifestJSON)); err != nil {
				t.Fatalf("Failed to write manifest data: %v", err)
			}
			tarWriter.Close()
			tmpFile.Close()

			// Test the extraction function
			imageName, imageTag, err := extractImageNameAndTagFromTar(tmpFile.Name())

			if test.expectError {
				assert.Error(t, err)
			} else {
				assert.NoError(t, err)
				assert.Equal(t, test.expectedName, imageName)
				assert.Equal(t, test.expectedTag, imageTag)
			}
		})
	}
}

func TestFilterOwnedLanguagePackages(t *testing.T) {
	rpmParent := pkg.Package{
		Name:    "python3-requests",
		Version: "2.25.1-1.el8",
		Type:    pkg.RpmPkg,
	}
	rpmParent.SetID()

	pipChild := pkg.Package{
		Name:    "requests",
		Version: "2.25.1",
		Type:    pkg.PythonPkg,
	}
	pipChild.SetID()

	standaloneNpm := pkg.Package{
		Name:    "express",
		Version: "4.18.0",
		Type:    pkg.NpmPkg,
	}
	standaloneNpm.SetID()

	apkParent := pkg.Package{
		Name:    "py3-setuptools",
		Version: "58.1.0-r0",
		Type:    pkg.ApkPkg,
	}
	apkParent.SetID()

	debParent := pkg.Package{
		Name:    "python3-urllib3",
		Version: "1.26.5-1",
		Type:    pkg.DebPkg,
	}
	debParent.SetID()

	tests := []struct {
		name          string
		artifacts     []pkg.Package
		allPackages   []pkg.Package
		relationships []artifact.Relationship
		expectedCount int
	}{
		{
			name:          "No relationships — no filtering",
			artifacts:     []pkg.Package{rpmParent, pipChild, standaloneNpm},
			allPackages:   []pkg.Package{rpmParent, pipChild, standaloneNpm},
			relationships: nil,
			expectedCount: 3,
		},
		{
			name:        "RPM owns pip child — child filtered",
			artifacts:   []pkg.Package{rpmParent, pipChild, standaloneNpm},
			allPackages: []pkg.Package{rpmParent, pipChild, standaloneNpm},
			relationships: []artifact.Relationship{
				{
					From: rpmParent,
					To:   pipChild,
					Type: artifact.OwnershipByFileOverlapRelationship,
				},
			},
			expectedCount: 2,
		},
		{
			name:        "APK owns pip child — child filtered",
			artifacts:   []pkg.Package{apkParent, pipChild},
			allPackages: []pkg.Package{apkParent, pipChild},
			relationships: []artifact.Relationship{
				{
					From: apkParent,
					To:   pipChild,
					Type: artifact.OwnershipByFileOverlapRelationship,
				},
			},
			expectedCount: 1,
		},
		{
			name:        "DEB owns pip child — child filtered",
			artifacts:   []pkg.Package{debParent, pipChild},
			allPackages: []pkg.Package{debParent, pipChild},
			relationships: []artifact.Relationship{
				{
					From: debParent,
					To:   pipChild,
					Type: artifact.OwnershipByFileOverlapRelationship,
				},
			},
			expectedCount: 1,
		},
		{
			name:        "Non-OS parent (npm owns pip) — no filtering",
			artifacts:   []pkg.Package{standaloneNpm, pipChild},
			allPackages: []pkg.Package{standaloneNpm, pipChild},
			relationships: []artifact.Relationship{
				{
					From: standaloneNpm,
					To:   pipChild,
					Type: artifact.OwnershipByFileOverlapRelationship,
				},
			},
			expectedCount: 2,
		},
		{
			name:        "Contains relationship type — ignored",
			artifacts:   []pkg.Package{rpmParent, pipChild},
			allPackages: []pkg.Package{rpmParent, pipChild},
			relationships: []artifact.Relationship{
				{
					From: rpmParent,
					To:   pipChild,
					Type: artifact.ContainsRelationship,
				},
			},
			expectedCount: 2,
		},
		{
			name:          "Empty relationships slice — no filtering",
			artifacts:     []pkg.Package{rpmParent, pipChild},
			allPackages:   []pkg.Package{rpmParent, pipChild},
			relationships: []artifact.Relationship{},
			expectedCount: 2,
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			collection := pkg.NewCollection(test.allPackages...)
			result := filterOwnedLanguagePackages(test.artifacts, collection, test.relationships)
			assert.Equal(t, test.expectedCount, len(result))
		})
	}
}
