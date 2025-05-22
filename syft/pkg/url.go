package pkg

import (
	"sort"
	"strings"

	"github.com/anchore/packageurl-go"
	"github.com/anchore/syft/syft/linux"
)

const (
	PURLQualifierArch   = "arch"
	PURLQualifierCPES   = "cpes"
	PURLQualifierDistro = "distro"
	PURLQualifierEpoch  = "epoch"
	PURLQualifierVCSURL = "vcs_url"

	// PURLQualifierUpstream this qualifier is not in the pURL spec, but is used by grype to perform indirect matching based on source information
	PURLQualifierUpstream = "upstream"

	purlCargoPkgType  = "cargo"
	purlGradlePkgType = "gradle"
)

type PURLOptionsDistro int

const (
	DistroVersion PURLOptionsDistro = iota // Default value
	DistroCodename
)

type PURLOptions struct {
	DistroQualifier PURLOptionsDistro
}

// String representation of distro qualifier options, use for mapping
// configuration value to enum.
var purlOptionsDistroQualifier = map[PURLOptionsDistro]string{
	DistroVersion:  "version",
	DistroCodename: "codename",
}

func (po PURLOptionsDistro) String() string {
	return purlOptionsDistroQualifier[po]
}

func PURLDistroQualifiers() []string {
	vars := make([]string, len(purlOptionsDistroQualifier))
	for _, s := range(purlOptionsDistroQualifier) {
		vars = append(vars, s)
	}
	return vars
}

func PURLQualifiers(vars map[string]string, release *linux.Release, opts *PURLOptions) (q packageurl.Qualifiers) {
	keys := make([]string, 0, len(vars))
	for k := range vars {
		keys = append(keys, k)
	}
	sort.Strings(keys)

	for _, k := range keys {
		val := vars[k]
		if val == "" {
			continue
		}
		q = append(q, packageurl.Qualifier{
			Key:   k,
			Value: vars[k],
		})
	}

	var distroQualifiers []string

	if release == nil {
		return q
	}

	switch (opts.DistroQualifier) {
	case DistroVersion:
		if release.ID != "" {
			distroQualifiers = append(distroQualifiers, release.ID)
		}
		if release.VersionID != "" {
			distroQualifiers = append(distroQualifiers, release.VersionID)
		} else if release.BuildID != "" {
			distroQualifiers = append(distroQualifiers, release.BuildID)
		}
	case DistroCodename:
		if release.VersionCodename != "" {
			distroQualifiers = append(distroQualifiers, release.VersionCodename)
		}
	}

	if len(distroQualifiers) > 0 {
		q = append(q, packageurl.Qualifier{
			Key:   PURLQualifierDistro,
			Value: strings.Join(distroQualifiers, "-"),
		})
	}

	return q
}
