package ca

import (
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"math/big"
	"time"

	"deleteonerror.com/tyinypki/internal/data"
)

func PublishRevocationList() error {
	n, err := getNextCRLNumber()
	if err != nil {
		return err
	}
	file, err := generateCRL(n)
	if err != nil {
		return err
	}

	cert := getCaCertificate()

	data.Publish(file, cert.Subject.CommonName+".crl")
	return nil
}

func getLatestCRL() (*x509.RevocationList, error) {
	data, err := data.GetLatestCRL()
	if err != nil {
		return nil, err
	}
	if len(data) == 0 {
		return nil, nil
	}

	block, _ := pem.Decode(data)
	crl, err := x509.ParseRevocationList(block.Bytes)
	if err != nil {
		return nil, err
	}
	return crl, nil
}

func getNextCRLNumber() (*big.Int, error) {
	data, err := data.GetLatestCRL()
	if err != nil {
		return nil, err
	}
	if data == nil {
		return new(big.Int), nil
	}

	block, _ := pem.Decode(data)
	crl, err := x509.ParseRevocationList(block.Bytes)
	if err != nil {
		return nil, err
	}

	crlNumber := crl.Number

	return crlNumber.Add(crlNumber, big.NewInt(1)), nil
}

func generateCRL(number *big.Int) (string, error) {

	rawCerts, err := data.GetRevokedCertificates()
	if err != nil {
		return "", err
	}

	revokedCertificates, err := convertCertificatesToCRL(rawCerts)
	if err != nil {
		return "", err
	}

	nextId, err := getNextCRLNumber()
	if err != nil {
		return "", err
	}

	cert := getCaCertificate()

	crlTemplate := &x509.RevocationList{
		Number:              nextId,
		ThisUpdate:          time.Now(),
		NextUpdate:          time.Now().Add(120 * 24 * time.Hour),
		RevokedCertificates: revokedCertificates,
		Issuer:              cert.Issuer,
		AuthorityKeyId:      cert.SubjectKeyId,
	}

	// if CaCert.KeyUsage&x509.KeyUsageCRLSign == 0 {
	// 	clog.WriteWarning(CaCert.Issuer.CommonName)
	// 	fmt.Printf("var3: %v\n", CaCert)
	// }

	// clog.WriteInfo(keyUsageToString(CaCert.KeyUsage))
	privkey := getPrivateKey()
	crlBytes, err := x509.CreateRevocationList(rand.Reader, crlTemplate, &cert, &privkey)
	if err != nil {
		return "", err
	}

	crlPemBlock := &pem.Block{
		Type:  "X509 CRL",
		Bytes: crlBytes,
	}

	filename, err := data.WriteCRL(pem.EncodeToMemory(crlPemBlock), nextId.String())
	if err != nil {
		return "", err
	}

	return filename, nil
}

func convertCertificatesToCRL(certificates [][]byte) ([]pkix.RevokedCertificate, error) {
	result := []pkix.RevokedCertificate{}

	for _, data := range certificates {
		cert, err := x509.ParseCertificate(data)
		if err != nil {
			return nil, err
		}

		// ToDo: revocation date is wrong and I have to find a better solution like
		// reading the old crl adn use the date from the old crl or store the revocation in fs
		revokedCert := pkix.RevokedCertificate{
			SerialNumber:   cert.SerialNumber,
			RevocationTime: time.Now(),
		}

		result = append(result, revokedCert)
	}

	return result, nil
}
