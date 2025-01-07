package syftPackagesExtractor

import (
	"encoding/base64"
	"encoding/json"
	"errors"
	"github.com/anchore/stereoscope/pkg/image"
	"github.com/rs/zerolog/log"
	"os"
	"path/filepath"
	"strings"
)

// PodmanAuth represents the structure of Podman's auth.json file
type PodmanAuth struct {
	Auths map[string]struct {
		Auth string `json:"auth"`
	} `json:"auths"`
}

// LoadPodmanAuth loads and parses Podman's auth.json file
func LoadPodmanAuth() (*PodmanAuth, error) {
	homeDir, err := os.UserHomeDir()
	if err != nil {
		log.Debug().Err(err).Msg("failed to get user home directory")
		return nil, errors.New("failed to get user home directory")
	}

	configPath := filepath.Join(homeDir, ".config", "containers", "auth.json")
	data, err := os.ReadFile(configPath)
	if err != nil {
		log.Debug().Err(err).Msg("failed attempt to read Podman config file")
		return nil, errors.New("failed attempt to read Podman config file")
	}
	log.Debug().Msgf("podman config file found: %s", configPath)

	var podmanAuth PodmanAuth
	if err := json.Unmarshal(data, &podmanAuth); err != nil {
		log.Debug().Err(err).Msg("failed to parse Podman config file")
		return nil, errors.New("failed to parse Podman config file")
	}

	return &podmanAuth, nil
}

// ParseAuth decodes the base64-encoded auth string into username and password
func ParseAuth(auth string) (string, string, error) {
	decoded, err := base64.StdEncoding.DecodeString(auth)
	if err != nil {
		log.Debug().Err(err).Msg("failed to decode auth string")
		return "", "", errors.New("failed to decode auth string")
	}

	parts := strings.SplitN(string(decoded), ":", 2)
	if len(parts) != 2 {
		log.Debug().Msg("invalid auth format")
		return "", "", errors.New("invalid auth format")
	}

	return parts[0], parts[1], nil
}

// CreateRegistryCredentials creates RegistryCredentials from Podman auth.json
func CreateRegistryCredentials(authConfig *PodmanAuth) ([]image.RegistryCredentials, error) {
	var credentials []image.RegistryCredentials

	for registry, auth := range authConfig.Auths {
		username, password, err := ParseAuth(auth.Auth)
		if err != nil {
			log.Debug().Err(err).Str("registry", registry).Msg("failed to parse credentials for registry")
			continue // Skip the current entry and proceed with others
		}

		credentials = append(credentials, image.RegistryCredentials{
			Authority: registry,
			Username:  username,
			Password:  password,
		})
	}
	log.Debug().Msgf("podman credentials found: %v", len(credentials))

	return credentials, nil
}
