package syftPackagesExtractor

import (
	"sort"
	"unicode/utf8"

	"github.com/anchore/syft/syft/file"
	"github.com/anchore/syft/syft/pkg"
	"github.com/rs/zerolog/log"
)

// Caps on the image labels and package file paths added to the resolution output. They keep the
// result (and the payload sent to the backend) bounded; anything above them is truncated and logged.
const (
	maxLabelsPerImage   = 256
	maxLabelKeyLength   = 4096
	maxLabelValueLength = 4096
	maxPathsPerPackage  = 100
	maxPathLength       = 4096
)

// extractImageLabels returns the OCI config labels, capped. It never returns nil: reaching this point
// means the image config was read, so an image without labels is an empty map ("extracted, none"),
// not nil ("not extracted").
func extractImageLabels(labels map[string]string) map[string]string {
	result := make(map[string]string, len(labels))
	if len(labels) == 0 {
		return result
	}

	// Sort the keys so which labels survive the cap is deterministic.
	keys := make([]string, 0, len(labels))
	droppedKeys := 0
	for k := range labels {
		// A key can't be truncated without risking collisions, so an absurdly long one is dropped.
		if len(k) > maxLabelKeyLength {
			droppedKeys++
			continue
		}
		keys = append(keys, k)
	}
	sort.Strings(keys)
	if droppedKeys > 0 {
		log.Warn().Msgf("Dropped %d labels whose key is longer than %d bytes", droppedKeys, maxLabelKeyLength)
	}

	if len(keys) > maxLabelsPerImage {
		log.Warn().Msgf("Image has %d labels, keeping the first %d", len(keys), maxLabelsPerImage)
		keys = keys[:maxLabelsPerImage]
	}

	truncated := 0
	for _, k := range keys {
		v := labels[k]
		if len(v) > maxLabelValueLength {
			v = truncateUTF8(v, maxLabelValueLength)
			truncated++
		}
		result[k] = v
	}
	if truncated > 0 {
		log.Warn().Msgf("Truncated %d label values to %d bytes", truncated, maxLabelValueLength)
	}
	return result
}

// extractPackageFilePaths returns the distinct, sorted paths of the package's primary-evidence
// locations (the files that identify the package, e.g. a package.json or dpkg status entry). When no
// location is marked primary, all locations are used. Capped; the result is nil when there are none.
func extractPackageFilePaths(locations file.LocationSet) []string {
	all := locations.ToSlice()

	var primary []file.Location
	for _, l := range all {
		if l.Annotations[pkg.EvidenceAnnotationKey] == pkg.PrimaryEvidenceAnnotation {
			primary = append(primary, l)
		}
	}
	if len(primary) == 0 {
		primary = all
	}

	seen := make(map[string]struct{}, len(primary))
	var paths []string
	truncated := false
	for _, l := range primary {
		p := l.RealPath
		if p == "" {
			continue
		}
		if len(p) > maxPathLength {
			p = truncateUTF8(p, maxPathLength)
			truncated = true
		}
		if _, ok := seen[p]; ok {
			continue
		}
		seen[p] = struct{}{}
		paths = append(paths, p)
	}
	sort.Strings(paths)

	if len(paths) > maxPathsPerPackage {
		log.Warn().Msgf("Package has %d file paths, keeping the first %d", len(paths), maxPathsPerPackage)
		paths = paths[:maxPathsPerPackage]
	}
	if truncated {
		log.Warn().Msgf("Truncated package file paths to %d bytes", maxPathLength)
	}
	return paths
}

// mergeDuplicateLocations returns the first package of a group of same name+version duplicates with the
// locations of its true duplicates merged in, so the layer IDs and file paths of the duplicates are not
// lost when only one of them is kept. A duplicate is a package with the same name, version and
// ecosystem: packages that merely share a name+version across ecosystems (an npm and a pypi "foo@1.0")
// are different packages and are not merged. It builds a new location set; the inputs are not mutated.
func mergeDuplicateLocations(group []pkg.Package) pkg.Package {
	chosen := group[0]
	if len(group) == 1 {
		return chosen
	}
	chosenEcosystem := packageTypeToPackageManager(chosen.Type)

	var all []file.Location
	merged := 0
	for _, p := range group {
		if p.Name != chosen.Name || p.Version != chosen.Version || packageTypeToPackageManager(p.Type) != chosenEcosystem {
			continue
		}
		all = append(all, p.Locations.ToSlice()...)
		merged++
	}
	if merged <= 1 {
		return chosen
	}
	chosen.Locations = file.NewLocationSet(all...)
	return chosen
}

// truncateUTF8 cuts s to at most max bytes without splitting a multi-byte character.
func truncateUTF8(s string, max int) string {
	if len(s) <= max {
		return s
	}
	cut := max
	for cut > 0 && !utf8.RuneStart(s[cut]) {
		cut--
	}
	return s[:cut]
}
