package pkg

import (
	"sort"
	"strings"
	"text/template"

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

// This would (probably) be the place to optionally support template strings for
// the PURL qualifiers...
//
func PURLQualifiers(vars map[string]string, release *linux.Release) (q packageurl.Qualifiers) {
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

	if release.ID != "" {
		distroQualifiers = append(distroQualifiers, release.ID)
	}

	if release.VersionID != "" {
		distroQualifiers = append(distroQualifiers, release.VersionID)
	} else if release.BuildID != "" {
		distroQualifiers = append(distroQualifiers, release.BuildID)
	}

	if len(distroQualifiers) > 0 {
		q = append(q, packageurl.Qualifier{
			Key:   PURLQualifierDistro,
			Value: strings.Join(distroQualifiers, "-"),
		})
	}

	return q
}

func PURLTemplateQualifiers(vars map[string]string, release *linux.Release, tstring string) (q packageurl.Qualifiers) {

	if vars == nil {
		vars = map[string]string{}
	}

	tpl, err := template.New("qtemplate").Parse(tstring)
	if err != nil {
		return q
	}

	var releaseQualifiers strings.Builder

	tpl.Execute(&releaseQualifiers, release)

	qpairs := strings.SplitSeq(releaseQualifiers.String(), "&")

	for pair := range qpairs {
		if !strings.Contains(pair, "=") {
			continue
		}
		tvars := strings.Split(pair, "=")
		key, value := tvars[0], tvars[1]
		if key == "" || value == "" {
			continue
		}
		vars[key] = value
	}

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

	return q
}
