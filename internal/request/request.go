package request

import (
	"crypto/ecdsa"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"

	"deleteonerror.com/tyinypki/internal/logger"
	"deleteonerror.com/tyinypki/internal/model"
)

func CreateSubCaRequest(conf model.Config, key ecdsa.PrivateKey) []byte {

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

func CreateSimpleRequest(key ecdsa.PrivateKey, req model.CertificateRequest) ([]byte, error) {

	csr := &x509.CertificateRequest{
		Subject: pkix.Name{
			CommonName: req.CommonName,
		},
		DNSNames:       req.DNSNames,
		IPAddresses:    req.IPAddresses,
		EmailAddresses: req.EmailAddresses,
	}

	csrBytes, err := x509.CreateCertificateRequest(rand.Reader, csr, &key)
	if err != nil {
		logger.Error("%v", err)
	}
	return csrBytes, nil
}
