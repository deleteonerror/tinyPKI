package terminal

import (
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/asn1"
	"encoding/hex"
	"fmt"

	"deleteonerror.com/tyinypki/internal/logger"
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
		getextKeyUsage(ext.Value)
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

	x509KU := x509.KeyUsage(ku.At(0)<<7 | ku.At(1)<<6 | ku.At(2)<<5 | ku.At(3)<<4 |
		ku.At(4)<<3 | ku.At(5)<<2 | ku.At(6)<<1 | ku.At(7))

	fmt.Println("KeyUsage:", x509KU)
	if x509KU&x509.KeyUsageDigitalSignature != 0 {
		fmt.Println("Has Digital Signature")
	}
	if x509KU&x509.KeyUsageContentCommitment != 0 {
		fmt.Println("Has Content Commitment")
	}
	if x509KU&x509.KeyUsageKeyEncipherment != 0 {
		fmt.Println("Has Key Encipherment")
	}
	if x509KU&x509.KeyUsageDataEncipherment != 0 {
		fmt.Println("Has Data Encipherment")
	}
	if x509KU&x509.KeyUsageKeyAgreement != 0 {
		fmt.Println("Has Key Agreement")
	}
	if x509KU&x509.KeyUsageCertSign != 0 {
		fmt.Println("Has Cert Sign")
	}
	if x509KU&x509.KeyUsageCRLSign != 0 {
		fmt.Println("Has CRL Sign")
	}
	if x509KU&x509.KeyUsageEncipherOnly != 0 {
		fmt.Println("Has Encipher Only")
	}
	if x509KU&x509.KeyUsageDecipherOnly != 0 {
		fmt.Println("Has Decipher Only")
	}

}

func getCertType(raw []byte) {
	var bitString asn1.BitString
	_, err := asn1.Unmarshal(raw, &bitString)
	if err != nil {
		fmt.Printf("Failed to parse Certificate Type extension: %v\n", err)

	}

	fmt.Printf("Certificate Type: %v\n", bitString.Bytes)
}

func getextKeyUsage(raw []byte) {

	var keyUsages []asn1.ObjectIdentifier
	_, err := asn1.Unmarshal(raw, &keyUsages)
	if err != nil {
		fmt.Println("Error decoding extKeyUsage: ", err)
		return
	}

	//ref: https://www.iana.org/assignments/smi-numbers/smi-numbers.xhtml#smi-numbers-1.3.6.1.5.5.7.3
	extKeyUsages := []x509.ExtKeyUsage{}
	for _, ku := range keyUsages {
		fmt.Printf("%v\n", ku)
		switch {
		case ku.Equal(asn1.ObjectIdentifier{1, 3, 6, 1, 5, 5, 7, 3, 1}):
			extKeyUsages = append(extKeyUsages, x509.ExtKeyUsageServerAuth)
		case ku.Equal(asn1.ObjectIdentifier{1, 3, 6, 1, 5, 5, 7, 3, 2}):
			extKeyUsages = append(extKeyUsages, x509.ExtKeyUsageClientAuth)
		case ku.Equal(asn1.ObjectIdentifier{1, 3, 6, 1, 5, 5, 7, 3, 3}):
			extKeyUsages = append(extKeyUsages, x509.ExtKeyUsageCodeSigning)
		case ku.Equal(asn1.ObjectIdentifier{1, 3, 6, 1, 5, 5, 7, 3, 4}):
			extKeyUsages = append(extKeyUsages, x509.ExtKeyUsageEmailProtection)
		case ku.Equal(asn1.ObjectIdentifier{1, 3, 6, 1, 5, 5, 7, 3, 5}):
			extKeyUsages = append(extKeyUsages, x509.ExtKeyUsageIPSECEndSystem)
		case ku.Equal(asn1.ObjectIdentifier{1, 3, 6, 1, 5, 5, 7, 3, 6}):
			extKeyUsages = append(extKeyUsages, x509.ExtKeyUsageIPSECTunnel)
		case ku.Equal(asn1.ObjectIdentifier{1, 3, 6, 1, 5, 5, 7, 3, 7}):
			extKeyUsages = append(extKeyUsages, x509.ExtKeyUsageIPSECUser)
		case ku.Equal(asn1.ObjectIdentifier{1, 3, 6, 1, 5, 5, 7, 3, 8}):
			extKeyUsages = append(extKeyUsages, x509.ExtKeyUsageTimeStamping)
		case ku.Equal(asn1.ObjectIdentifier{1, 3, 6, 1, 5, 5, 7, 3, 9}):
			extKeyUsages = append(extKeyUsages, x509.ExtKeyUsageOCSPSigning)
		case ku.Equal(asn1.ObjectIdentifier{1, 3, 6, 1, 4, 1, 311, 10, 3, 3}):
			extKeyUsages = append(extKeyUsages, x509.ExtKeyUsageMicrosoftServerGatedCrypto)
		case ku.Equal(asn1.ObjectIdentifier{2, 16, 840, 1, 113730, 4, 1}):
			extKeyUsages = append(extKeyUsages, x509.ExtKeyUsageNetscapeServerGatedCrypto)
		case ku.Equal(asn1.ObjectIdentifier{1, 3, 6, 1, 4, 1, 311, 2, 1, 22}):
			extKeyUsages = append(extKeyUsages, x509.ExtKeyUsageMicrosoftCommercialCodeSigning)
		case ku.Equal(asn1.ObjectIdentifier{1, 3, 6, 1, 4, 1, 311, 61, 1, 1}):
			extKeyUsages = append(extKeyUsages, x509.ExtKeyUsageMicrosoftKernelCodeSigning)
		default:
			logger.Debug("Extended key usage %s not supported", ku.String())
		}
	}
	fmt.Printf("%v  count: %d\n", extKeyUsages, len(extKeyUsages))
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
