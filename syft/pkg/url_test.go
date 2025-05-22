package pkg

import (
	"testing"

	"github.com/stretchr/testify/assert"

	"github.com/anchore/syft/syft/linux"
)

func TestDistroQualifiersFromOptions(t *testing.T) {

	tests := []struct {
		name     string
		expected string
		vars     map[string]string
		options  PURLOptions
		release  linux.Release
	}{
		{
			name: "Distro qualifier with default options (version ID)",
			expected: "distro=debian-12",
			options: PURLOptions{},
			release: linux.Release{
				ID:              "debian",
				VersionCodename: "bullseye",
				VersionID:       "12",
			},
		},
		{
			name: "Distro qualifier with Debian distribution version",
			expected: "distro=debian-12",
			options: PURLOptions{
				DistroQualifier: DistroVersion,
			},
			release: linux.Release{
				ID:              "debian",
				VersionCodename: "bullseye",
				VersionID:       "12",
			},
		},
		{
			name: "Distro qualifier with Debian distribution codename",
			expected: "distro=bullseye",
			options: PURLOptions{
				DistroQualifier: DistroCodename,
			},
			release: linux.Release{
				ID:              "debian",
				VersionCodename: "bullseye",
				VersionID:       "12",
			},
		},
	}
	for _, test := range tests {
		t.Run(string(test.name), func(t *testing.T) {
			q := PURLQualifiers(test.vars, &test.release, &test.options)
			assert.Equal(t, test.expected, q.String())
		})
	}
}
