package syftPackagesExtractor

import (
	"testing"

	"github.com/Checkmarx/containers-types/types"
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
		{
			name: "All unsupported package types",
			packages: []pkg.Package{
				{Name: "test1", Version: "1.0", Type: pkg.UnknownPkg},
				{Name: "test2", Version: "2.0", Type: pkg.UnknownPkg},
			},
			expected: []pkg.Package{},
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
