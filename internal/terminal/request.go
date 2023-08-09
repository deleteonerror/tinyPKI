package terminal

import (
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/asn1"
	"encoding/hex"
	"fmt"

	"deleteonerror.com/tyinypki/internal/request"
)

func PrintRequest(csr x509.CertificateRequest) {

	fmt.Printf("Version: %d\n", csr.Version)
	fmt.Printf("Subject: %v\n", csr.Subject)
	fmt.Printf("Signature Algorithm: %v\n", csr.SignatureAlgorithm)
	fmt.Printf("Public Key Algorithm: %v\n", csr.PublicKeyAlgorithm)

	fmt.Println("-- Extensions")
	for _, ext := range csr.Extensions {
		writeExt(ext)
	}
	fmt.Println("-- Extra Extensions")

	for _, ext := range csr.ExtraExtensions {
		writeExt(ext)
	}

	for _, dns := range csr.DNSNames {
		fmt.Printf("DNSNames: %v\n", dns)
	}

	for _, mail := range csr.EmailAddresses {
		fmt.Printf("EmailAddresses: %v\n", mail)
	}
	for _, ip := range csr.IPAddresses {
		fmt.Printf("IPAddresses: %v\n", ip)
	}
	for _, uri := range csr.URIs {
		fmt.Printf("URIs: %v\n", uri)
	}

}

func writeExt(ext pkix.Extension) {

	name, ok := oidNames[ext.Id.String()]
	if !ok {
		name = "unknown"
	}
	fmt.Printf("oid: %s (%s)\n", ext.Id, name)
	fmt.Printf("Critical: %v\n", ext.Critical)

	switch ext.Id.String() {

	case "2.5.29.14":
		sk := getSki(ext.Value)
		fmt.Printf("ski: %s\n", sk)
	case "2.5.29.15":
		getKeyUsage(ext.Value)
	case "2.5.29.37":
		request.GetExtKeyUsage(ext.Value)
	case "2.16.840.1.113730.1.13":
		getComment(ext.Value)
	case "2.16.840.1.113730.1.1":
		getCertType(ext.Value)
	default:
		fmt.Println("#---")
		fmt.Printf("Value: % x\n", ext.Value)
	}
}

func getComment(raw []byte) {
	var com asn1.RawValue
	asn1.Unmarshal(raw, &com)

	fmt.Printf("%s\n", com.Bytes)
}

func getSki(raw []byte) string {

	var ski asn1.RawValue
	_, err := asn1.Unmarshal(raw, &ski)
	if err != nil {
		// Handle error
	}
	if ski.Tag != asn1.TagOctetString {
		// Handle error: SKI should be an OCTET STRING
	}
	return hex.EncodeToString(ski.Bytes)
}

func getKeyUsage(raw []byte) {

	var ku asn1.BitString
	_, err := asn1.Unmarshal(raw, &ku)
	if err != nil {
		fmt.Println("Error unmarshaling:", err)
		return
	}

	xk := x509.KeyUsage(ku.BitLength)
	fmt.Printf("ku %v\n", xk)
	usageStr := request.KeyUsageToString(xk)
	fmt.Println("Key Usages:", usageStr)
}

func getCertType(raw []byte) {
	var bitString asn1.BitString
	_, err := asn1.Unmarshal(raw, &bitString)
	if err != nil {
		fmt.Printf("Failed to parse Certificate Type extension: %v\n", err)

	}

	fmt.Printf("Certificate Type: %v\n", bitString.Bytes)
}

var oidNames = map[string]string{
	"2.5.29.17":              "Subject Alternative Name",
	"2.5.29.19":              "basicConstraints",
	"2.16.840.1.113730.1.1":  "cert-type",
	"2.5.29.15":              "keyUsage", //works
	"2.16.840.1.113730.1.13": "comment",  // works
	"2.5.29.14":              "subjectKeyIdentifier",
	"2.5.29.37":              "extKeyUsage", //works
}
