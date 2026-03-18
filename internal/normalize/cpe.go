package normalize

import (
	"fmt"
	"strings"
)

// CPE represents a parsed CPE 2.3 URI.
// Format: cpe:2.3:part:vendor:product:version:update:edition:language:sw_edition:target_sw:target_hw:other
type CPE struct {
	Part      string // a=application, o=os, h=hardware
	Vendor    string
	Product   string
	Version   string
	Update    string
	Edition   string
	Language  string
	SWEdition string
	TargetSW  string
	TargetHW  string
	Other     string
}

const wildcard = "*"
const notApplicable = "-"

// ParseCPE23 parses a CPE 2.3 formatted string.
// Returns an error if the string is not a valid CPE 2.3 URI.
func ParseCPE23(cpe string) (*CPE, error) {
	if !strings.HasPrefix(cpe, "cpe:2.3:") {
		return nil, fmt.Errorf("not a CPE 2.3 URI: %s", cpe)
	}

	parts := strings.Split(cpe, ":")
	if len(parts) != 13 {
		return nil, fmt.Errorf("CPE 2.3 must have 13 components, got %d: %s", len(parts), cpe)
	}

	return &CPE{
		Part:      parts[2],
		Vendor:    parts[3],
		Product:   parts[4],
		Version:   parts[5],
		Update:    parts[6],
		Edition:   parts[7],
		Language:  parts[8],
		SWEdition: parts[9],
		TargetSW:  parts[10],
		TargetHW:  parts[11],
		Other:     parts[12],
	}, nil
}

// String reconstructs the CPE 2.3 URI string.
func (c *CPE) String() string {
	return strings.Join([]string{
		"cpe", "2.3",
		c.Part, c.Vendor, c.Product, c.Version,
		c.Update, c.Edition, c.Language,
		c.SWEdition, c.TargetSW, c.TargetHW, c.Other,
	}, ":")
}

// IsWildcard returns true if the version component is a wildcard or not-applicable.
func (c *CPE) IsWildcard() bool {
	return c.Version == wildcard || c.Version == notApplicable
}

// VendorProduct returns the "vendor:product" pair — the primary matching key.
func (c *CPE) VendorProduct() string {
	return c.Vendor + ":" + c.Product
}

// MatchesVendorProduct returns true if the CPE's vendor and product match
// the given values. Wildcards match everything.
func (c *CPE) MatchesVendorProduct(vendor, product string) bool {
	vendorMatch := c.Vendor == wildcard || c.Vendor == vendor
	productMatch := c.Product == wildcard || c.Product == product
	return vendorMatch && productMatch
}
