package pkg

import (
	"testing"

	"github.com/stretchr/testify/assert"

	"github.com/anchore/syft/syft/linux"
)

func TestReleaseQualifiersFromTemplate(t *testing.T) {

	tests := []struct {
		name     string
		expected string
		vars     map[string]string
		template string
		release  linux.Release
	}{
		{
			name: "Distro qualifier with Debian distribution version",
			expected: "distro=debian-12",
			template: "distro={{ .ID }}-{{ .VersionID }}",
			release: linux.Release{
				ID:        "debian",
				VersionID: "12",
			},
		},
		{
			name: "Distro qualifier with Debian distribution codename",
			expected: "distro=bullseye",
			template: "distro={{ .VersionCodename }}",
			release: linux.Release{
				VersionCodename: "bullseye",
			},
		},
		{
			name:     "Distro qualifier with additional qualifier",
			expected: "arch=amd64&distro=bullseye",
			vars:     map[string]string{"arch": "amd64", "upstream": "https://example.com"},
			template: "distro={{ .VersionCodename }}",
			release: linux.Release{
				VersionCodename: "bullseye",
			},
		},
		{
			name:     "Distro qualifier with additional qualifiers",
			expected: "arch=amd64&distro=bullseye&upstream=https%3A%2F%2Fexample.com",
			vars:     map[string]string{"arch": "amd64", "upstream": "https://example.com"},
			template: "distro={{ .VersionCodename }}",
			release: linux.Release{
				VersionCodename: "bullseye",
			},
		},
	}

	for _, test := range tests {
		t.Run(string(test.name), func(t *testing.T) {
			q := PURLTemplateReleaseQualifiers(test.vars, &test.release, test.template)
			assert.Equal(t, test.expected,q.String())
		})
	}
}
