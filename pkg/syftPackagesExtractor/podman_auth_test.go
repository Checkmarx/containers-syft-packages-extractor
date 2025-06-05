package syftPackagesExtractor

import (
	"encoding/base64"
	"os"
	"path/filepath"
	"testing"

	"github.com/anchore/stereoscope/pkg/image"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestLoadPodmanAuth(t *testing.T) {
	tests := []struct {
		name          string
		setupAuthFile func(t *testing.T) string
		expected      *PodmanAuth
		expectError   bool
	}{
		{
			name: "Valid auth file",
			setupAuthFile: func(t *testing.T) string {
				// Create a temporary directory
				tempDir := t.TempDir()
				configDir := filepath.Join(tempDir, ".config", "containers")
				err := os.MkdirAll(configDir, 0755)
				require.NoError(t, err)

				// Create auth.json with valid content
				authContent := `{
					"auths": {
						"docker.io": {
							"auth": "dXNlcjpwYXNz"
						},
						"quay.io": {
							"auth": "cXVheXVzZXI6cXVheXBhc3M="
						}
					}
				}`
				authFile := filepath.Join(configDir, "auth.json")
				err = os.WriteFile(authFile, []byte(authContent), 0644)
				require.NoError(t, err)

				// Set HOME environment variable to temp directory
				os.Setenv("HOME", tempDir)
				return authFile
			},
			expected: &PodmanAuth{
				Auths: map[string]struct {
					Auth string `json:"auth"`
				}{
					"docker.io": {Auth: "dXNlcjpwYXNz"},
					"quay.io":   {Auth: "cXVheXVzZXI6cXVheXBhc3M="},
				},
			},
			expectError: false,
		},
		{
			name: "Invalid JSON in auth file",
			setupAuthFile: func(t *testing.T) string {
				tempDir := t.TempDir()
				configDir := filepath.Join(tempDir, ".config", "containers")
				err := os.MkdirAll(configDir, 0755)
				require.NoError(t, err)

				authFile := filepath.Join(configDir, "auth.json")
				err = os.WriteFile(authFile, []byte("invalid json"), 0644)
				require.NoError(t, err)

				os.Setenv("HOME", tempDir)
				return authFile
			},
			expected:    nil,
			expectError: true,
		},
		{
			name: "Missing auth file",
			setupAuthFile: func(t *testing.T) string {
				tempDir := t.TempDir()
				os.Setenv("HOME", tempDir)
				return ""
			},
			expected:    nil,
			expectError: true,
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			if test.setupAuthFile != nil {
				test.setupAuthFile(t)
			}

			result, err := LoadPodmanAuth()
			if test.expectError {
				assert.Error(t, err)
				assert.Nil(t, result)
			} else {
				assert.NoError(t, err)
				assert.Equal(t, test.expected, result)
			}
		})
	}
}

func TestParseAuth(t *testing.T) {
	tests := []struct {
		name         string
		auth         string
		expectedUser string
		expectedPass string
		expectError  bool
	}{
		{
			name:         "Valid auth string",
			auth:         base64.StdEncoding.EncodeToString([]byte("user:pass")),
			expectedUser: "user",
			expectedPass: "pass",
			expectError:  false,
		},
		{
			name:         "Invalid base64",
			auth:         "invalid-base64",
			expectedUser: "",
			expectedPass: "",
			expectError:  true,
		},
		{
			name:         "Invalid format (no colon)",
			auth:         base64.StdEncoding.EncodeToString([]byte("invalidformat")),
			expectedUser: "",
			expectedPass: "",
			expectError:  true,
		},
		{
			name:         "Empty auth string",
			auth:         "",
			expectedUser: "",
			expectedPass: "",
			expectError:  true,
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			user, pass, err := ParseAuth(test.auth)
			if test.expectError {
				assert.Error(t, err)
				assert.Empty(t, user)
				assert.Empty(t, pass)
			} else {
				assert.NoError(t, err)
				assert.Equal(t, test.expectedUser, user)
				assert.Equal(t, test.expectedPass, pass)
			}
		})
	}
}

func TestCreateRegistryCredentials(t *testing.T) {
	tests := []struct {
		name        string
		authConfig  *PodmanAuth
		expected    []image.RegistryCredentials
		expectError bool
	}{
		{
			name: "Valid auth config",
			authConfig: &PodmanAuth{
				Auths: map[string]struct {
					Auth string `json:"auth"`
				}{
					"docker.io": {Auth: base64.StdEncoding.EncodeToString([]byte("user:pass"))},
					"quay.io":   {Auth: base64.StdEncoding.EncodeToString([]byte("quayuser:quaypass"))},
				},
			},
			expected: []image.RegistryCredentials{
				{
					Authority: "docker.io",
					Username:  "user",
					Password:  "pass",
				},
				{
					Authority: "quay.io",
					Username:  "quayuser",
					Password:  "quaypass",
				},
			},
			expectError: false,
		},
		{
			name: "Auth config with invalid credentials",
			authConfig: &PodmanAuth{
				Auths: map[string]struct {
					Auth string `json:"auth"`
				}{
					"docker.io": {Auth: "invalid-auth"},
					"quay.io":   {Auth: base64.StdEncoding.EncodeToString([]byte("quayuser:quaypass"))},
				},
			},
			expected: []image.RegistryCredentials{
				{
					Authority: "quay.io",
					Username:  "quayuser",
					Password:  "quaypass",
				},
			},
			expectError: false,
		},
		{
			name:        "Nil auth config",
			authConfig:  nil,
			expected:    nil,
			expectError: false,
		},
		{
			name: "Empty auth config",
			authConfig: &PodmanAuth{
				Auths: map[string]struct {
					Auth string `json:"auth"`
				}{},
			},
			expected:    []image.RegistryCredentials{},
			expectError: false,
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			result, err := CreateRegistryCredentials(test.authConfig)
			if test.expectError {
				assert.Error(t, err)
			} else {
				assert.NoError(t, err)
				assert.Equal(t, len(test.expected), len(result))
				for i, expected := range test.expected {
					assert.Equal(t, expected.Authority, result[i].Authority)
					assert.Equal(t, expected.Username, result[i].Username)
					assert.Equal(t, expected.Password, result[i].Password)
				}
			}
		})
	}
}
