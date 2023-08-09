package ca

import (
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"math/big"
	"time"

	"deleteonerror.com/tyinypki/internal/data"
	"deleteonerror.com/tyinypki/internal/logger"
	"deleteonerror.com/tyinypki/internal/model"
)

func PublishRevocationList() error {

	file, err := generateCRL()
	if err != nil {
		logger.Error("%v", err)
		return err
	}
	if file == "" {
		return nil
	}

	cert := getCaCertificate()

	data.Publish(file, cert.Subject.CommonName+".crl")
	return nil
}

func getLatestCRL() (*x509.RevocationList, error) {
	data, err := data.GetLatestCRL()
	if err != nil {
		logger.Error("%v", err)
		return nil, err
	}
	if len(data) == 0 {
		return nil, nil
	}

	block, _ := pem.Decode(data)
	crl, err := x509.ParseRevocationList(block.Bytes)
	if err != nil {
		logger.Error("%v", err)
		return nil, err
	}
	return crl, nil
}

func generateCRL() (string, error) {

	rawCerts, err := data.GetRevokedCertificatesFromCaStore()
	if err != nil {
		logger.Error("%v", err)
		return "", err
	}

	revokedCertificates, err := convertCertificatesToCRL(rawCerts)
	if err != nil {
		logger.Error("%v", err)
		return "", err
	}

	nextId := cfg.Config.LastCRLNumber
	nextId.Add(nextId, big.NewInt(1))

	cert := getCaCertificate()

	crlTemplate := &x509.RevocationList{
		Number:              nextId,
		ThisUpdate:          time.Now(),
		NextUpdate:          time.Now().Add(120 * 24 * time.Hour),
		RevokedCertificates: revokedCertificates,
		Issuer:              cert.Issuer,
		AuthorityKeyId:      cert.SubjectKeyId,
	}

	privkey := getPrivateKey()
	crlBytes, err := x509.CreateRevocationList(rand.Reader, crlTemplate, &cert, &privkey)
	if err != nil {
		logger.Error("%v", err)
		return "", err
	}

	crlPemBlock := &pem.Block{
		Type:  "X509 CRL",
		Bytes: crlBytes,
	}

	filename, err := data.WriteCRL(pem.EncodeToMemory(crlPemBlock), nextId.String())
	if err != nil {
		logger.Error("%v", err)
		return "", err
	}

	updateLastCrl(nextId)
	return filename, nil
}

func convertCertificatesToCRL(certificates []model.FileContentWithPath) ([]pkix.RevokedCertificate, error) {
	result := []pkix.RevokedCertificate{}

	for _, cert := range certificates {
		cert, err := parseCertificate(cert.Data)
		if err != nil || len(cert.Raw) == 0 || cert.NotAfter.Before(time.Now()) {
			continue
		}
		// ToDo: revocation date is wrong and I have to find a better solution like
		// reading the old crl and use the date from the old crl or store the revocation in fs
		revokedCert := pkix.RevokedCertificate{
			SerialNumber:   cert.SerialNumber,
			RevocationTime: time.Now(),
		}

		result = append(result, revokedCert)
	}

	return result, nil
}
