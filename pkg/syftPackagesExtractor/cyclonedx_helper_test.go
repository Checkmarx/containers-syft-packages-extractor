package syftPackagesExtractor

import (
	"bytes"
	"compress/gzip"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io"
	"testing"

	"github.com/anchore/syft/syft/pkg"
	"github.com/anchore/syft/syft/sbom"
	"github.com/anchore/syft/syft/source"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestGenerateCycloneDxSBOM(t *testing.T) {
	// Create a test SBOM
	catalog := pkg.NewCollection()

	// Add test packages
	testPkg1 := pkg.Package{
		Name:    "test-package-1",
		Version: "1.0.0",
		Type:    pkg.NpmPkg,
		PURL:    "pkg:npm/test-package-1@1.0.0",
	}
	testPkg1.SetID()
	catalog.Add(testPkg1)

	testPkg2 := pkg.Package{
		Name:    "test-package-2",
		Version: "2.0.0",
		Type:    pkg.PythonPkg,
		Licenses: pkg.NewLicenseSet(
			pkg.NewLicense("MIT"),
		),
	}
	testPkg2.SetID()
	catalog.Add(testPkg2)

	// Create test SBOM
	testSBOM := sbom.SBOM{
		Descriptor: sbom.Descriptor{
			Name:    "syft",
			Version: "test-version",
		},
		Artifacts: sbom.Artifacts{
			Packages: catalog,
		},
		Source: source.Description{
			Metadata: source.ImageMetadata{},
		},
	}

	// Generate CycloneDX SBOM
	result, err := tryGenerateCycloneDxSBOM(testSBOM)
	require.NoError(t, err, "Should successfully generate CycloneDX SBOM")
	assert.NotEmpty(t, result)

	// Decode and verify the result
	decodedData, err := base64.StdEncoding.DecodeString(result)
	require.NoError(t, err)

	// Decompress
	reader, err := gzip.NewReader(bytes.NewReader(decodedData))
	require.NoError(t, err)
	defer reader.Close()

	decompressedData, err := io.ReadAll(reader)
	require.NoError(t, err)

	// Parse JSON
	var cycloneDx map[string]interface{}
	err = json.Unmarshal(decompressedData, &cycloneDx)
	require.NoError(t, err)

	// Verify structure
	assert.Equal(t, "CycloneDX", cycloneDx["bomFormat"])
	assert.Contains(t, cycloneDx["specVersion"], "1.") // Could be 1.4 or 1.5
	assert.Contains(t, cycloneDx["serialNumber"], "urn:uuid:")
	assert.NotNil(t, cycloneDx["metadata"])

	// Check components
	components, ok := cycloneDx["components"].([]interface{})
	require.True(t, ok)
	assert.Len(t, components, 2)

	// Find components by name (order is not guaranteed)
	var comp1, comp2 map[string]interface{}
	for _, comp := range components {
		c := comp.(map[string]interface{})
		if c["name"] == "test-package-1" {
			comp1 = c
		} else if c["name"] == "test-package-2" {
			comp2 = c
		}
	}

	// Verify first component
	require.NotNil(t, comp1, "test-package-1 should be present")
	assert.Equal(t, "library", comp1["type"])
	assert.Equal(t, "test-package-1", comp1["name"])
	assert.Equal(t, "1.0.0", comp1["version"])
	assert.Equal(t, "pkg:npm/test-package-1@1.0.0", comp1["purl"])

	// Verify second component with license
	require.NotNil(t, comp2, "test-package-2 should be present")
	assert.Equal(t, "library", comp2["type"])
	assert.Equal(t, "test-package-2", comp2["name"])
	assert.Equal(t, "2.0.0", comp2["version"])
	licenses, ok := comp2["licenses"].([]interface{})
	require.True(t, ok)
	assert.Len(t, licenses, 1)
	license := licenses[0].(map[string]interface{})
	// Check for either license structure (could be expression or license object)
	if licenseChoice, hasChoice := license["license"]; hasChoice {
		// CycloneDX 1.4+ structure
		licenseObj := licenseChoice.(map[string]interface{})
		if licenseID, hasID := licenseObj["id"]; hasID {
			assert.Equal(t, "MIT", licenseID)
		} else if licenseName, hasName := licenseObj["name"]; hasName {
			assert.Equal(t, "MIT", licenseName)
		}
	} else {
		// Older structure
		if licenseID, hasID := license["id"]; hasID {
			assert.Equal(t, "MIT", licenseID)
		} else if licenseName, hasName := license["name"]; hasName {
			assert.Equal(t, "MIT", licenseName)
		}
	}
}

func TestCycloneDxSBOMWithEmptyCatalog(t *testing.T) {
	// Create a minimal test SBOM with no packages
	catalog := pkg.NewCollection()

	testSBOM := sbom.SBOM{
		Descriptor: sbom.Descriptor{
			Name:    "syft",
			Version: "test-version",
		},
		Artifacts: sbom.Artifacts{
			Packages: catalog,
		},
	}

	// Test the function (it should generate valid SBOM even with no packages)
	result, err := tryGenerateCycloneDxSBOM(testSBOM)
	require.NoError(t, err)
	assert.NotEmpty(t, result)

	// Verify it's base64 encoded
	decodedData, err := base64.StdEncoding.DecodeString(result)
	assert.NoError(t, err)

	// Verify it's gzipped
	reader, err := gzip.NewReader(bytes.NewReader(decodedData))
	require.NoError(t, err)
	defer reader.Close()

	decompressedData, err := io.ReadAll(reader)
	require.NoError(t, err)

	// Verify it's valid JSON
	var cycloneDx map[string]interface{}
	err = json.Unmarshal(decompressedData, &cycloneDx)
	require.NoError(t, err)

	// Should have empty or nil components
	components, exists := cycloneDx["components"]
	if exists && components != nil {
		// If components field exists and is not nil, it should be an empty array
		componentsArray, ok := components.([]interface{})
		require.True(t, ok, "components should be an array if it exists")
		assert.Empty(t, componentsArray)
	}
	// It's also valid for components to not exist or be nil when there are no packages
}

func TestCycloneDxSBOMCompression(t *testing.T) {
	// Test that the output is properly compressed
	catalog := pkg.NewCollection()

	// Add many packages to ensure compression is effective
	for i := 0; i < 100; i++ {
		p := pkg.Package{
			Name:    fmt.Sprintf("package-%d", i),
			Version: fmt.Sprintf("1.0.%d", i),
			Type:    pkg.NpmPkg,
		}
		p.SetID()
		catalog.Add(p)
	}

	testSBOM := sbom.SBOM{
		Descriptor: sbom.Descriptor{
			Name:    "syft",
			Version: "test-version",
		},
		Artifacts: sbom.Artifacts{
			Packages: catalog,
		},
	}

	result, err := tryGenerateCycloneDxSBOM(testSBOM)
	require.NoError(t, err)

	// Decode base64
	compressedData, err := base64.StdEncoding.DecodeString(result)
	require.NoError(t, err)

	// Decompress to check compression ratio
	reader, err := gzip.NewReader(bytes.NewReader(compressedData))
	require.NoError(t, err)
	defer reader.Close()

	decompressedData, err := io.ReadAll(reader)
	require.NoError(t, err)

	// Compressed data should be significantly smaller than decompressed
	compressionRatio := float64(len(decompressedData)) / float64(len(compressedData))
	assert.Greater(t, compressionRatio, 2.0, "Compression ratio should be at least 2:1")
}
