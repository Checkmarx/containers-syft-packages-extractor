package syftPackagesExtractor

import (
	"bytes"
	"compress/gzip"
	"encoding/base64"
	"fmt"

	"github.com/anchore/syft/syft/format"
	"github.com/anchore/syft/syft/sbom"
)

// tryGenerateCycloneDxSBOM generates a zipped, base64 encoded CycloneDX SBOM using the official syft encoder
func tryGenerateCycloneDxSBOM(s sbom.SBOM) (string, error) {
	// Get all available encoders
	encoders := format.Encoders()

	// Try to find and use the CycloneDX JSON encoder
	for _, enc := range encoders {
		// Check for various possible CycloneDX encoder IDs
		if enc.ID() == "cyclonedx-json" || enc.ID() == "cyclonedx-1-json" ||
			enc.ID() == "cyclonedx-1.4-json" || enc.ID() == "cyclonedx-1.5-json" {
			// Found a CycloneDX encoder, use it
			cycloneDxBytes, err := format.Encode(s, enc)
			if err != nil {
				// Try next encoder if this one fails
				continue
			}

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

			// Base64 encode the compressed data
			encodedSBOM := base64.StdEncoding.EncodeToString(compressedBuffer.Bytes())
			return encodedSBOM, nil
		}
	}

	// If no CycloneDX encoder was found, return an error
	return "", fmt.Errorf("CycloneDX encoder not found in available formats")
}
