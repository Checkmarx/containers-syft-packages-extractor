package syftPackagesExtractor

import (
	"encoding/json"
	"fmt"
	"strings"
	"testing"

	"github.com/Checkmarx/containers-types/types"
	"github.com/anchore/syft/syft/file"
	"github.com/anchore/syft/syft/pkg"
	"github.com/anchore/syft/syft/source"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func primaryLocation(path, fsID string) file.Location {
	loc := file.NewLocation(path).WithAnnotation(pkg.EvidenceAnnotationKey, pkg.PrimaryEvidenceAnnotation)
	loc.Coordinates.FileSystemID = fsID
	return loc
}

func supportingLocation(path, fsID string) file.Location {
	loc := file.NewLocation(path).WithAnnotation(pkg.EvidenceAnnotationKey, pkg.SupportingEvidenceAnnotation)
	loc.Coordinates.FileSystemID = fsID
	return loc
}

func TestExtractImageLabels(t *testing.T) {
	t.Run("nil input is extracted-with-none, never nil", func(t *testing.T) {
		got := extractImageLabels(nil)
		assert.NotNil(t, got)
		assert.Empty(t, got)
	})

	t.Run("empty input stays an empty non-nil map", func(t *testing.T) {
		got := extractImageLabels(map[string]string{})
		assert.NotNil(t, got)
		assert.Empty(t, got)
	})

	t.Run("values are copied", func(t *testing.T) {
		in := map[string]string{"env": "prod", "empty": ""}
		got := extractImageLabels(in)
		assert.Equal(t, in, got)
		got["env"] = "changed"
		assert.Equal(t, "prod", in["env"], "result must not alias the input map")
	})

	t.Run("more labels than the cap keeps the first keys in sorted order", func(t *testing.T) {
		in := map[string]string{}
		for i := 0; i < maxLabelsPerImage+50; i++ {
			in["k"+padInt(i)] = "v"
		}
		got := extractImageLabels(in)
		assert.Len(t, got, maxLabelsPerImage)
		assert.Contains(t, got, "k"+padInt(0))
		assert.NotContains(t, got, "k"+padInt(maxLabelsPerImage+49))
	})

	t.Run("long values are truncated without splitting a character", func(t *testing.T) {
		long := strings.Repeat("é", maxLabelValueLength) // 2 bytes each
		got := extractImageLabels(map[string]string{"k": long})
		assert.LessOrEqual(t, len(got["k"]), maxLabelValueLength)
		assert.True(t, strings.HasPrefix(long, got["k"]))
		assert.Equal(t, strings.ToValidUTF8(got["k"], ""), got["k"])
	})
}

func padInt(i int) string { return fmt.Sprintf("%06d", i) }

func TestExtractPackageFilePaths(t *testing.T) {
	t.Run("no locations returns nil", func(t *testing.T) {
		assert.Nil(t, extractPackageFilePaths(file.NewLocationSet()))
	})

	t.Run("only primary evidence paths are used", func(t *testing.T) {
		got := extractPackageFilePaths(file.NewLocationSet(
			primaryLocation("/app/package.json", "sha256:a"),
			supportingLocation("/app/node_modules/x/index.js", "sha256:a"),
		))
		assert.Equal(t, []string{"/app/package.json"}, got)
	})

	t.Run("falls back to all locations when none is primary", func(t *testing.T) {
		got := extractPackageFilePaths(file.NewLocationSet(
			file.NewLocation("/b"), file.NewLocation("/a"),
		))
		assert.Equal(t, []string{"/a", "/b"}, got)
	})

	t.Run("same path in several layers is reported once and sorted", func(t *testing.T) {
		got := extractPackageFilePaths(file.NewLocationSet(
			primaryLocation("/z/app.jar", "sha256:l1"),
			primaryLocation("/z/app.jar", "sha256:l2"),
			primaryLocation("/a/app.jar", "sha256:l1"),
		))
		assert.Equal(t, []string{"/a/app.jar", "/z/app.jar"}, got)
	})

	t.Run("capped per package", func(t *testing.T) {
		var locs []file.Location
		for i := 0; i < maxPathsPerPackage+20; i++ {
			locs = append(locs, primaryLocation("/p/"+padInt(i), "sha256:a"))
		}
		got := extractPackageFilePaths(file.NewLocationSet(locs...))
		assert.Len(t, got, maxPathsPerPackage)
	})

	t.Run("long path is truncated", func(t *testing.T) {
		long := "/" + strings.Repeat("a", maxPathLength+10)
		got := extractPackageFilePaths(file.NewLocationSet(primaryLocation(long, "sha256:a")))
		require.Len(t, got, 1)
		assert.Len(t, got[0], maxPathLength)
	})
}

func TestMergeDuplicateLocations(t *testing.T) {
	a := pkg.Package{Name: "n", Version: "1", Type: pkg.NpmPkg, Locations: file.NewLocationSet(primaryLocation("/layer1/pkg", "sha256:l1"))}
	b := pkg.Package{Name: "n", Version: "1", Type: pkg.NpmPkg, Locations: file.NewLocationSet(primaryLocation("/layer2/pkg", "sha256:l2"))}

	t.Run("single package is returned unchanged", func(t *testing.T) {
		got := mergeDuplicateLocations([]pkg.Package{a})
		assert.Equal(t, []string{"l1"}, extractPackageLayerIds(got.Locations))
	})

	t.Run("duplicates contribute their layers and paths", func(t *testing.T) {
		got := mergeDuplicateLocations([]pkg.Package{a, b})
		assert.ElementsMatch(t, []string{"l1", "l2"}, extractPackageLayerIds(got.Locations))
		assert.Equal(t, []string{"/layer1/pkg", "/layer2/pkg"}, extractPackageFilePaths(got.Locations))
	})

	t.Run("layer IDs are not repeated when duplicates share a layer", func(t *testing.T) {
		c := pkg.Package{Name: "n", Version: "1", Type: pkg.NpmPkg, Locations: file.NewLocationSet(primaryLocation("/layer1/other", "sha256:l1"))}
		got := mergeDuplicateLocations([]pkg.Package{a, c})
		assert.Equal(t, []string{"l1"}, extractPackageLayerIds(got.Locations))
		assert.Equal(t, []string{"/layer1/other", "/layer1/pkg"}, extractPackageFilePaths(got.Locations))
	})

	t.Run("same name and version in another ecosystem is not merged", func(t *testing.T) {
		npm := pkg.Package{Name: "foo", Version: "1.0", Type: pkg.NpmPkg, Locations: file.NewLocationSet(primaryLocation("/n/package.json", "sha256:n"))}
		py := pkg.Package{Name: "foo", Version: "1.0", Type: pkg.PythonPkg, Locations: file.NewLocationSet(primaryLocation("/p/METADATA", "sha256:p"))}
		got := mergeDuplicateLocations([]pkg.Package{npm, py})
		assert.Equal(t, []string{"n"}, extractPackageLayerIds(got.Locations))
		assert.Equal(t, []string{"/n/package.json"}, extractPackageFilePaths(got.Locations))
	})

	t.Run("input packages are not mutated", func(t *testing.T) {
		_ = mergeDuplicateLocations([]pkg.Package{a, b})
		assert.Equal(t, []string{"/layer1/pkg"}, extractPackageFilePaths(a.Locations))
	})
}

func TestExtractImage_Labels(t *testing.T) {
	var res ContainerResolution
	extractImage("debian:12", types.ImageModel{}, source.ImageMetadata{Labels: nil}, "img", "tag", &res)
	assert.NotNil(t, res.ContainerImage.Labels, "image config was read, so labels are extracted-with-none")
	assert.Empty(t, res.ContainerImage.Labels)

	extractImage("debian:12", types.ImageModel{}, source.ImageMetadata{Labels: map[string]string{"a": "b"}}, "img", "tag", &res)
	assert.Equal(t, map[string]string{"a": "b"}, res.ContainerImage.Labels)
}

func TestResolutionJSON_LabelsAndPaths(t *testing.T) {
	marshal := func(r ContainerResolution) map[string]any {
		b, err := json.Marshal(r)
		require.NoError(t, err)
		var m map[string]any
		require.NoError(t, json.Unmarshal(b, &m))
		return m
	}
	image := func(m map[string]any) map[string]any { return m["ContainerImage"].(map[string]any) }

	t.Run("not extracted serializes as null", func(t *testing.T) {
		img := image(marshal(createEmptyContainerResolution()))
		v, present := img["Labels"]
		assert.True(t, present)
		assert.Nil(t, v)
	})

	t.Run("extracted with none serializes as an empty object", func(t *testing.T) {
		img := image(marshal(ContainerResolution{ContainerImage: ContainerImage{Labels: map[string]string{}}}))
		assert.Equal(t, map[string]any{}, img["Labels"])
	})

	t.Run("labels and package paths use PascalCase keys", func(t *testing.T) {
		m := marshal(ContainerResolution{
			ContainerImage:    ContainerImage{Labels: map[string]string{"env": "prod"}},
			ContainerPackages: []ContainerPackage{{Name: "n", PackageFilePaths: []string{"/a"}}},
		})
		assert.Equal(t, map[string]any{"env": "prod"}, image(m)["Labels"])
		p := m["ContainerPackages"].([]any)[0].(map[string]any)
		assert.Equal(t, []any{"/a"}, p["PackageFilePaths"])
	})
}

func TestGetSyftArtifacts_MergesDuplicateLocations(t *testing.T) {
	npmLayer1 := pkg.Package{Name: "foo", Version: "1.0", Type: pkg.NpmPkg, Locations: file.NewLocationSet(primaryLocation("/a/package.json", "sha256:l1"))}
	npmLayer2 := pkg.Package{Name: "foo", Version: "1.0", Type: pkg.NpmPkg, Locations: file.NewLocationSet(primaryLocation("/b/package.json", "sha256:l2"))}
	unsupported := pkg.Package{Name: "foo", Version: "1.0", Type: pkg.BinaryPkg, Locations: file.NewLocationSet(primaryLocation("/bin/foo", "sha256:l3"))}
	python := pkg.Package{Name: "foo", Version: "1.0", Type: pkg.PythonPkg, Locations: file.NewLocationSet(primaryLocation("/p/METADATA", "sha256:l4"))}

	t.Run("same ecosystem duplicates keep one package with merged layers and paths", func(t *testing.T) {
		got := getSyftArtifactsWithoutUnsupportedTypesDuplications(pkg.NewCollection(npmLayer1, npmLayer2, unsupported))
		require.Len(t, got, 1)
		assert.ElementsMatch(t, []string{"l1", "l2"}, extractPackageLayerIds(got[0].Locations))
		assert.Equal(t, []string{"/a/package.json", "/b/package.json"}, extractPackageFilePaths(got[0].Locations))
	})

	t.Run("a package of another ecosystem with the same name and version does not leak in", func(t *testing.T) {
		got := getSyftArtifactsWithoutUnsupportedTypesDuplications(pkg.NewCollection(npmLayer1, python))
		require.Len(t, got, 1)
		ids := extractPackageLayerIds(got[0].Locations)
		assert.Len(t, ids, 1)
	})
}
