package request

import (
	"crypto/x509"
	"encoding/asn1"
	"fmt"
	"strings"

	"deleteonerror.com/tyinypki/internal/logger"
)

func KeyUsageToString(ku x509.KeyUsage) string {
	var usages []string

	if ku&x509.KeyUsageDigitalSignature != 0 {
		usages = append(usages, "Digital Signature")
	}
	if ku&x509.KeyUsageContentCommitment != 0 {
		usages = append(usages, "Content Commitment")
	}
	if ku&x509.KeyUsageKeyEncipherment != 0 {
		usages = append(usages, "Key Encipherment")
	}
	if ku&x509.KeyUsageDataEncipherment != 0 {
		usages = append(usages, "Data Encipherment")
	}
	if ku&x509.KeyUsageKeyAgreement != 0 {
		usages = append(usages, "Key Agreement")
	}
	if ku&x509.KeyUsageCertSign != 0 {
		usages = append(usages, "Cert Sign")
	}
	if ku&x509.KeyUsageCRLSign != 0 {
		usages = append(usages, "CRL Sign")
	}
	if ku&x509.KeyUsageEncipherOnly != 0 {
		usages = append(usages, "Encipher Only")
	}
	if ku&x509.KeyUsageDecipherOnly != 0 {
		usages = append(usages, "Decipher Only")
	}

	return strings.Join(usages, ", ")
}

func GetExtKeyUsage(raw []byte) {

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
