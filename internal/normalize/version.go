package normalize

import (
	"regexp"
	"strings"

	"github.com/Masterminds/semver/v3"
)

// VersionScheme describes how a version string was parsed.
type VersionScheme string

const (
	VersionSchemeSemVer    VersionScheme = "semver"
	VersionSchemeCalVer    VersionScheme = "calver"
	VersionSchemeArbitrary VersionScheme = "arbitrary"
	VersionSchemeUnknown   VersionScheme = "unknown"
)

// NormalizedVersion is the result of parsing a raw version string.
type NormalizedVersion struct {
	Raw        string
	Normalized string
	Scheme     VersionScheme
	SemVer     *semver.Version // non-nil if Scheme == SemVer
	IsUnknown  bool
	ParseError string
}

// ErrIncomparableVersions is returned when two versions cannot be compared
// because one or both have unknown scheme.
var ErrIncomparableVersions = errIncomparable("versions are incomparable")

type errIncomparable string

func (e errIncomparable) Error() string { return string(e) }

// knownUnknowns are version strings that are always treated as unknown.
var knownUnknowns = map[string]bool{
	"latest":  true,
	"stable":  true,
	"current": true,
	"unknown": true,
	"n/a":     true,
	"":        true,
}

// debianSuffixRe matches Debian/Ubuntu packaging suffixes like "-4+deb11u3".
var debianSuffixRe = regexp.MustCompile(`[-+](?:deb|ubuntu|dfsg|build)\S*$`)

// alpineSuffixRe matches Alpine packaging suffixes like "-alpine", "-r1".
var alpineSuffixRe = regexp.MustCompile(`[-_](?:alpine|r\d+).*$`)

// opensshRe matches OpenSSH-style versions like "9.6p1".
var opensshRe = regexp.MustCompile(`^(\d+\.\d+)p(\d+)$`)

// Normalize parses a raw version string into a NormalizedVersion.
// It never panics — normalization failures are represented in ParseError.
func Normalize(raw string) NormalizedVersion {
	lower := strings.ToLower(strings.TrimSpace(raw))

	if knownUnknowns[lower] {
		return NormalizedVersion{
			Raw:       raw,
			Scheme:    VersionSchemeUnknown,
			IsUnknown: true,
		}
	}

	// Try to clean up common suffixes before semver parsing.
	cleaned := stripDistroSuffix(lower)

	// Attempt semver parse.
	if sv, err := semver.NewVersion(cleaned); err == nil {
		return NormalizedVersion{
			Raw:        raw,
			Normalized: sv.Original(),
			Scheme:     VersionSchemeSemVer,
			SemVer:     sv,
		}
	}

	// Attempt calver: YYYYMMDD or YYYY.MM.DD
	if isCalVer(cleaned) {
		return NormalizedVersion{
			Raw:        raw,
			Normalized: cleaned,
			Scheme:     VersionSchemeCalVer,
		}
	}

	// Give up.
	return NormalizedVersion{
		Raw:        raw,
		Scheme:     VersionSchemeUnknown,
		IsUnknown:  true,
		ParseError: "could not parse version: " + raw,
	}
}

// Compare returns -1, 0, or 1 for v1 < v2, v1 == v2, v1 > v2.
// Returns ErrIncomparableVersions if either version is unknown.
func Compare(v1, v2 NormalizedVersion) (int, error) {
	if v1.IsUnknown || v2.IsUnknown {
		return 0, ErrIncomparableVersions
	}
	if v1.SemVer != nil && v2.SemVer != nil {
		return v1.SemVer.Compare(v2.SemVer), nil
	}
	// Calver or arbitrary string comparison
	if v1.Normalized < v2.Normalized {
		return -1, nil
	}
	if v1.Normalized > v2.Normalized {
		return 1, nil
	}
	return 0, nil
}

// InRange returns true if version satisfies the semver constraint string.
// constraint uses semver constraint syntax, e.g. "< 2.9.0", ">= 1.0.0, < 2.0.0".
// Returns false (not an error) if version is unknown.
func InRange(version NormalizedVersion, constraint string) (bool, error) {
	if version.IsUnknown {
		return false, nil
	}
	if version.SemVer == nil {
		return false, nil // cannot evaluate non-semver against a range
	}
	c, err := semver.NewConstraint(constraint)
	if err != nil {
		return false, err
	}
	return c.Check(version.SemVer), nil
}

func stripDistroSuffix(v string) string {
	// OpenSSH: 9.6p1 → 9.6.1
	if m := opensshRe.FindStringSubmatch(v); m != nil {
		return m[1] + "." + m[2]
	}
	// Debian/Ubuntu suffixes
	v = debianSuffixRe.ReplaceAllString(v, "")
	// Alpine suffixes
	v = alpineSuffixRe.ReplaceAllString(v, "")
	return v
}

var calverRe = regexp.MustCompile(`^\d{4}[\.\-]?\d{2}[\.\-]?\d{2}`)

func isCalVer(v string) bool {
	return calverRe.MatchString(v)
}
