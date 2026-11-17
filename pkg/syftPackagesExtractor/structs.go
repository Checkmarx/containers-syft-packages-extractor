package syftPackagesExtractor

type ImageConfig struct {
	History []HistoryConfig `json:"history"`
	Rootfs  RootfsConfig    `json:"rootfs"`
}

type HistoryConfig struct {
	CreatedBy  string `json:"created_by"`
	EmptyLayer bool   `json:"empty_layer"`
}

type RootfsConfig struct {
	DiffIds []string `json:"diff_ids"`
}

type ContainerResolution struct {
	ContainerImage    ContainerImage
	ContainerPackages []ContainerPackage
	CycloneDxSBOM     string `json:"cycloneDxSBOM,omitempty"` // Zipped, base64 encoded CycloneDX SBOM
}

type ContainerImage struct {
	ImageName      string
	ImageTag       string
	Distribution   string
	ImageHash      string
	ImageId        string
	ImageLocations []ImageLocation
	Layers         []string
	History        []Layer
	// Labels are the OCI image config labels. nil means "not extracted" (e.g. a tar/OCI input that was
	// skipped); an empty, non-nil map means "extracted, the image has none". Consumers rely on this
	// difference, so it must serialize as null vs {}.
	Labels    map[string]string
	Status    string `json:"status,omitempty"`    // Status of the resolution: "Resolved" or "Failed"
	ScanError string `json:"ScanError,omitempty"` // Error message if status is "Failed"
}

type ImageLocation struct {
	Origin     string
	Path       string
	FinalStage bool
}

type ContainerPackage struct {
	Name          string
	Version       string
	Distribution  string
	Type          string
	SourceName    string
	SourceVersion string
	Licenses      []string
	LayerIds      []string
	// PackageFilePaths are the distinct primary-evidence file paths Syft found the package at.
	PackageFilePaths []string
}

type Layer struct {
	Order   int
	Size    int64
	LayerId string
	Command string
}
