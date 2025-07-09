package syftPackagesExtractor

import (
	"bytes"
	"compress/gzip"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"time"

	"github.com/anchore/syft/syft/format"
	"github.com/anchore/syft/syft/sbom"
	"github.com/google/uuid"
)

// generateCycloneDxSBOMFromJSON generates a zipped, base64 encoded CycloneDX SBOM
// This is a temporary implementation that converts the syft JSON to a minimal CycloneDX format
func generateCycloneDxSBOMFromJSON(s sbom.SBOM) (string, error) {
	// For now, we'll create a minimal CycloneDX structure
	// In a production implementation, you would use the proper CycloneDX encoder

	// Create a minimal CycloneDX structure
	cycloneDx := map[string]interface{}{
		"bomFormat":    "CycloneDX",
		"specVersion":  "1.4",
		"serialNumber": fmt.Sprintf("urn:uuid:%s", uuid.New().String()),
		"version":      1,
		"metadata": map[string]interface{}{
			"timestamp": time.Now().Format("2006-01-02T15:04:05Z"),
			"tools": []map[string]interface{}{
				{
					"vendor":  "anchore",
					"name":    s.Descriptor.Name,
					"version": s.Descriptor.Version,
				},
			},
		},
		"components": []map[string]interface{}{},
	}

	// Add components from packages
	components := []map[string]interface{}{}
	if s.Artifacts.Packages != nil {
		for p := range s.Artifacts.Packages.Enumerate() {
			component := map[string]interface{}{
				"type":    "library",
				"name":    p.Name,
				"version": p.Version,
			}

			if p.PURL != "" {
				component["purl"] = p.PURL
			}

			if len(p.Licenses.ToSlice()) > 0 {
				licenses := []map[string]interface{}{}
				for _, l := range p.Licenses.ToSlice() {
					license := map[string]interface{}{}
					if l.SPDXExpression != "" {
						license["id"] = l.SPDXExpression
					} else if l.Value != "" {
						license["name"] = l.Value
					}
					licenses = append(licenses, license)
				}
				component["licenses"] = licenses
			}

			components = append(components, component)
		}
	}
	cycloneDx["components"] = components

	// Convert to JSON
	jsonBytes, err := json.Marshal(cycloneDx)
	if err != nil {
		return "", fmt.Errorf("failed to marshal CycloneDX to JSON: %w", err)
	}

	// Compress using gzip
	var compressedBuffer bytes.Buffer
	gzipWriter := gzip.NewWriter(&compressedBuffer)
	_, err = gzipWriter.Write(jsonBytes)
	if err != nil {
		return "", fmt.Errorf("failed to compress CycloneDX SBOM: %w", err)
	}
	err = gzipWriter.Close()
	if err != nil {
		return "", fmt.Errorf("failed to close gzip writer: %w", err)
	}

	// Base64 encode the compressed data
	encodedSBOM := base64.StdEncoding.EncodeToString(compressedBuffer.Bytes())

	return encodedSBOM, nil
}

// This is a helper function that tries different methods to generate CycloneDX
func tryGenerateCycloneDxSBOM(s sbom.SBOM) (string, error) {
	// Try the standard format encoder first
	encoders := format.Encoders()
	for _, enc := range encoders {
		if enc.ID() == "cyclonedx-json" || enc.ID() == "cyclonedx-1-json" {
			cycloneDxBytes, err := format.Encode(s, enc)
			if err == nil {
				// Successfully encoded, now compress and base64
				var compressedBuffer bytes.Buffer
				gzipWriter := gzip.NewWriter(&compressedBuffer)
				_, err = gzipWriter.Write(cycloneDxBytes)
				if err != nil {
					return "", fmt.Errorf("failed to compress CycloneDX SBOM: %w", err)
				}
				err = gzipWriter.Close()
				if err != nil {
					return "", fmt.Errorf("failed to close gzip writer: %w", err)
				}

				encodedSBOM := base64.StdEncoding.EncodeToString(compressedBuffer.Bytes())
				return encodedSBOM, nil
			}
		}
	}

	// If the standard encoder is not available, use our fallback implementation
	return generateCycloneDxSBOMFromJSON(s)
}
