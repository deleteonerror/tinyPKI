package request

import (
	"crypto/ecdsa"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"

	"deleteonerror.com/tyinypki/internal/logger"
	"deleteonerror.com/tyinypki/internal/model"
)

func CreateSubCaRequest(conf model.SetupConfig, key ecdsa.PrivateKey) []byte {

	subject := pkix.Name{
		Organization:       []string{conf.Organization},
		OrganizationalUnit: []string{conf.OrganizationalUnit},
		Country:            []string{conf.Country},
		CommonName:         conf.Name,
	}

	csr := &x509.CertificateRequest{
		Subject: subject,
	}

	csrBytes, err := x509.CreateCertificateRequest(rand.Reader, csr, &key)
	if err != nil {
		logger.Error("%v", err)
	}
	return csrBytes
}
