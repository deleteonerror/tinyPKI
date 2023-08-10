package model

import "net"

// CertificateRequest represents the details needed to create a certificate request.
type CertificateRequest struct {
	Type string
	// The common name to be used in the certificate, typically representing the hostname.
	CommonName string
	// The DNS names that should be included in the Subject Alternative Name (SAN) field.
	DNSNames []string
	// The email addresses that should be included in the SAN field
	EmailAddresses []string
	// The IP addresses that should be included in the SAN field.
	IPAddresses []net.IP
	// The Uniform Resource Identifiers (URIs) that should be included in the SAN field.
	URIs []string
}
