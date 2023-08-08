package ca

import (
	"crypto/x509"
	"encoding/asn1"
	"errors"
	"fmt"

	"deleteonerror.com/tyinypki/internal/data"
	"deleteonerror.com/tyinypki/internal/logger"
	"deleteonerror.com/tyinypki/internal/terminal"
)

func ValidateRequest(filePath string) (bool, error) {
	asn1Req, err := data.GetX509CertificateRequest(filePath)
	if err != nil {
		logger.Error("Unable to read file")
		return false, err
	}

	csr, err := x509.ParseCertificateRequest(asn1Req)
	if err != nil {
		logger.Error("%v", err)
		return false, err
	}

	terminal.PrintRequest(*csr)

	return true, nil
}

func getKeyUsage(csr x509.CertificateRequest) (x509.KeyUsage, error) {
	for _, ext := range csr.Extensions {

		if ext.Id.String() == "2.5.29.15" {

			var ku asn1.BitString
			_, err := asn1.Unmarshal(ext.Value, &ku)
			if err != nil {
				logger.Error("Error unmarshaling: %v", err)
				return x509.KeyUsageDigitalSignature, errors.New("no keyusage found")
			}

			x509KU := x509.KeyUsage(ku.At(0)<<7 | ku.At(1)<<6 | ku.At(2)<<5 | ku.At(3)<<4 |
				ku.At(4)<<3 | ku.At(5)<<2 | ku.At(6)<<1 | ku.At(7))

			return x509KU, nil
		}

	}
	return x509.KeyUsageDigitalSignature, errors.New("no keyusage found")
}

func getExtKeyUsage(csr x509.CertificateRequest) ([]x509.ExtKeyUsage, error) {
	for _, ext := range csr.Extensions {

		if ext.Id.String() == "2.5.29.37" {

			var keyUsages []asn1.ObjectIdentifier
			_, err := asn1.Unmarshal(ext.Value, &keyUsages)
			if err != nil {
				fmt.Println("Error decoding extKeyUsage: ", err)
				return nil, err
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
			return extKeyUsages, nil
		}
	}
	return nil, nil
}
