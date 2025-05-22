package options

import (
	"fmt"

	"github.com/anchore/clio"
	"github.com/anchore/syft/syft/cataloging"
	"github.com/anchore/syft/syft/pkg"
)

type packageConfig struct {
	SearchUnindexedArchives         bool `yaml:"search-unindexed-archives" json:"search-unindexed-archives" mapstructure:"search-unindexed-archives"`
	SearchIndexedArchives           bool `yaml:"search-indexed-archives" json:"search-indexed-archives" mapstructure:"search-indexed-archives"`
	ExcludeBinaryOverlapByOwnership bool `yaml:"exclude-binary-overlap-by-ownership" json:"exclude-binary-overlap-by-ownership" mapstructure:"exclude-binary-overlap-by-ownership"` // exclude synthetic binary packages owned by os package files

	PackageURL packageURLConfig `yaml:"purl" json:"purl" mapstructure:"purl"`
}

type packageURLConfig struct {
	PackageURLDistroQualifier string `yaml:"distro-qualifier" json:"distro-qualifier" mapstructure:"distro-qualifier"`
}

var _ interface {
	clio.PostLoader
	clio.FieldDescriber
} = (*packageConfig)(nil)

func (o *packageConfig) DescribeFields(descriptions clio.FieldDescriptionSet) {
	descriptions.Add(&o.SearchIndexedArchives, `search within archives that do contain a file index to search against (zip)
note: for now this only applies to the java package cataloger`)
	descriptions.Add(&o.SearchUnindexedArchives, `search within archives that do not contain a file index to search against (tar, tar.gz, tar.bz2, etc)
note: enabling this may result in a performance impact since all discovered compressed tars will be decompressed
note: for now this only applies to the java package cataloger`)
	descriptions.Add(&o.ExcludeBinaryOverlapByOwnership, `allows users to exclude synthetic binary packages from the sbom
these packages are removed if an overlap with a non-synthetic package is found`)
	descriptions.Add(&o.PackageURL.PackageURLDistroQualifier, `select what to use as distribution qualifier when generating PURLs`)
}

func (o *packageConfig) PostLoad() error {
	distroQualifiers := pkg.PURLDistroQualifiers()
	for _, v := range(distroQualifiers) {
		if o.PackageURL.PackageURLDistroQualifier == v {
			return nil
		}
	}

	return fmt.Errorf("invalid configuration value for distribution qualifier: %q", o.PackageURL.PackageURLDistroQualifier)
}

func DefaultPURLOptions() pkg.PURLOptions {
	return pkg.PURLOptions{
		DistroQualifier: pkg.DistroVersion,
	}
}

func defaultPackageConfig() packageConfig {
	c := cataloging.DefaultArchiveSearchConfig()
	return packageConfig{
		SearchIndexedArchives:           c.IncludeIndexedArchives,
		SearchUnindexedArchives:         c.IncludeUnindexedArchives,
		ExcludeBinaryOverlapByOwnership: true,
		PackageURL:                      packageURLConfig{
			PackageURLDistroQualifier: pkg.DistroVersion.String(),
		},
	}
}
