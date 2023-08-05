package ca

import (
	"crypto/x509"
	"encoding/pem"

	"deleteonerror.com/tyinypki/internal/logger"
)

func parseCertificate(raw []byte) (x509.Certificate, error) {

	block, _ := pem.Decode(raw)

	cert, err := x509.ParseCertificate(block.Bytes)
	if err != nil {
		logger.Error("%v", err)
		return x509.Certificate{}, err
	}
	return *cert, nil

}
