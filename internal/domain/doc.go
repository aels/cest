// Package domain provides a narrow, allocation-conscious path from X.509 DER
// to normalized domain names.
//
// ExtractCertificate accepts a complete DER Certificate. ExtractTBSCertificate
// accepts the DER TBSCertificate carried by CT precertificate entries. Both
// preserve DNS SAN order, append a distinct legacy CN, normalize each name,
// discard invalid names, and deduplicate within the certificate.
//
// NewFilter creates the specification's built-in filter plus an optional
// case-insensitive custom regular expression. Use Filter.Apply after extraction.
package domain
