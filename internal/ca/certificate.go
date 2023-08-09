package ca

import (
	"crypto/x509"
	"encoding/pem"

	"deleteonerror.com/tyinypki/internal/data"
	"deleteonerror.com/tyinypki/internal/logger"
)

func getCaCertificate() x509.Certificate {
	if len(cfg.Certificate.Raw) == 0 {
		derCert, err := data.ReadCaCertificate()
		if err != nil {
			logger.Debug("Cold not read Certificate file: %v", err)
			return x509.Certificate{}
		}
		block, _ := pem.Decode(derCert)

		pCaCert, err := x509.ParseCertificate(block.Bytes)
		if err != nil {
			logger.Error("Cold not pars Certificate file: %v", err)
		}
		logger.Debug("Certificate loaded.")
		cfg.Certificate = *pCaCert

	}
	return cfg.Certificate
}

func parseCertificate(raw []byte) (x509.Certificate, error) {

	block, _ := pem.Decode(raw)

	cert, err := x509.ParseCertificate(block.Bytes)
	if err != nil {
		logger.Error("%v", err)
		return x509.Certificate{}, err
	}
	return *cert, nil

}
