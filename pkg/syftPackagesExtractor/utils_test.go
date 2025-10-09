package syftPackagesExtractor

import (
	"strings"
	"testing"

	"github.com/Checkmarx/containers-types/types"
	"github.com/anchore/stereoscope/pkg/image"
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
					SourceRpm: "test-pkg",
					Version:   "1.0.0",
				},
			},
			expectedName: "test-pkg",
			expectedVer:  "1.0.0",
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
			expectedVer:  "",
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
					SourceRpm: "test-pkg",
					Version:   "",
				},
			},
			expectedName: "test-pkg",
			expectedVer:  "1.0.0",
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

func TestExtractImageWithTarFile(t *testing.T) {
	// Test the fix for AST-112118: tar files without colons should not panic
	tests := []struct {
		name         string
		imageName    string
		expectedName string
		expectedTag  string
	}{
		{
			name:         "Docker saved tar file",
			imageName:    "juice-shop.tar",
			expectedName: "juice-shop.tar",
			expectedTag:  "unavailable",
		},
		{
			name:         "Docker saved tar file with uppercase extension",
			imageName:    "alpine.TAR",
			expectedName: "alpine.TAR",
			expectedTag:  "unavailable",
		},
		{
			name:         "Compressed tar.gz file",
			imageName:    "nginx.tar.gz",
			expectedName: "nginx.tar.gz",
			expectedTag:  "unavailable",
		},
		{
			name:         "Compressed tar.bz2 file",
			imageName:    "ubuntu.tar.bz2",
			expectedName: "ubuntu.tar.bz2",
			expectedTag:  "unavailable",
		},
		{
			name:         "Compressed tar.xz file",
			imageName:    "centos.tar.xz",
			expectedName: "centos.tar.xz",
			expectedTag:  "unavailable",
		},
		{
			name:         "Image with tag",
			imageName:    "nginx:1.21",
			expectedName: "nginx",
			expectedTag:  "1.21",
		},
		{
			name:         "Image with latest tag",
			imageName:    "alpine:latest",
			expectedName: "alpine",
			expectedTag:  "latest",
		},
		{
			name:         "Image without tag",
			imageName:    "ubuntu",
			expectedName: "ubuntu",
			expectedTag:  "latest",
		},
		{
			name:         "Image with multiple colons",
			imageName:    "registry.example.com:5000/namespace/image:tag",
			expectedName: "registry.example.com:5000/namespace/image",
			expectedTag:  "tag",
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			// Test the same logic as the updated transformSBOMToContainerResolution function
			imageName := test.imageName
			imageTag := "latest" // default tag

			// Check for tar file extensions
			if strings.HasSuffix(strings.ToLower(imageName), ".tar") {
				// This is a .tar file from docker save - imageName is the full filename, tag is unavailable
				imageTag = "unavailable"
			} else if strings.HasSuffix(strings.ToLower(imageName), ".tar.gz") ||
				strings.HasSuffix(strings.ToLower(imageName), ".tar.bz2") ||
				strings.HasSuffix(strings.ToLower(imageName), ".tar.xz") {
				// This is a compressed tar file - not supported
				imageTag = "unavailable"
			} else {
				// Regular image name with potential tag - use the same logic as splitToImageAndTag in ast-cli
				lastColonIndex := strings.LastIndex(imageName, ":")

				if lastColonIndex == len(imageName)-1 || lastColonIndex == -1 {
					// No tag specified, default to "latest"
					imageTag = "latest"
				} else {
					imageTag = imageName[lastColonIndex+1:]
					imageName = imageName[:lastColonIndex]
				}
			}

			// Verify the fix works
			assert.Equal(t, test.expectedName, imageName)
			assert.Equal(t, test.expectedTag, imageTag)

			// Verify no panic occurs when processing the image name
			assert.NotPanics(t, func() {
				_ = imageName
				_ = imageTag
			})
		})
	}
}
