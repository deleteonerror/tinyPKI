package ca

import (
	"crypto/rand"
	"crypto/sha256"
	"crypto/x509"
	"encoding/hex"
	"encoding/pem"
	"math/big"
	"net/url"
	"time"

	"deleteonerror.com/tyinypki/internal/data"
	"deleteonerror.com/tyinypki/internal/logger"
)

func IssuePendingCaRequests() error {
	requests, err := data.GetCertificateRequests()
	if err != nil {
		logger.Error("%v", err)
		return err
	}

	if len(requests) == 0 {
		logger.Debug("no pending requests found")
		return nil
	}

	for _, req := range requests {

		block, _ := pem.Decode(req.Data)

		x509Req, err := x509.ParseCertificateRequest(block.Bytes)
		if err != nil {
			logger.Error("Failed to parse request %s: %v", req.Name, err)
			continue
		}
		//check if request key usage contains cer and crl sign
		err = createIntermediateCertificate(x509Req)
		if err != nil {
			logger.Error("Failed to Issue request %s: %v", req.Name, err)
			continue
		}
		data.ArchiveRequest(req.Name)
	}

	return nil
}

func IssuePendingRequests() error {
	requests, err := data.GetCertificateRequests()
	if err != nil {
		logger.Error("%v", err)
		return err
	}

	if len(requests) == 0 {
		logger.Debug("no pending requests found")
		return nil
	}

	for _, req := range requests {

		block, _ := pem.Decode(req.Data)
		if block == nil {
			logger.Debug("Skipped %s, no pem encoded file", req.Path)
			continue
		}
		logger.Debug("%s\n", req.Name)
		x509Req, err := x509.ParseCertificateRequest(block.Bytes)
		if err != nil {
			logger.Error("Failed to parse request %s: %v", req.Name, err)
			continue
		}

		err = createCertificate(x509Req)
		if err != nil {
			logger.Error("Failed to Issue request %s: %v", req.Name, err)
			continue
		}
		data.ArchiveRequest(req.Name)
	}

	return nil
}

func createCertificate(csr *x509.CertificateRequest) error {

	serialNumberLimit := new(big.Int).Lsh(big.NewInt(1), 128)
	serialNumber, err := rand.Int(rand.Reader, serialNumberLimit)
	if err != nil {
		logger.Error("%v", err)
		return err
	}

	publicKey, err := x509.MarshalPKIXPublicKey(csr.PublicKey)
	if err != nil {
		logger.Error("%v", err)
		return err
	}
	ski := sha256.Sum256(publicKey)

	ku, err := getKeyUsage(*csr)
	if err != nil {
		logger.Error("No keyusage in Request! Key usage set to Digital signature only")
	}

	eku, err := getExtKeyUsage(*csr)
	if err != nil {
		logger.Error("No EKU in Request! Extended Key usage not set.")
	}

	template := &x509.Certificate{
		SerialNumber:          serialNumber,
		Subject:               csr.Subject,
		NotBefore:             time.Now(),
		NotAfter:              time.Now().AddDate(1, 0, 0),
		IsCA:                  false,
		BasicConstraintsValid: false,
		MaxPathLen:            0,
		SubjectKeyId:          ski[:],
		DNSNames:              csr.DNSNames,
		EmailAddresses:        csr.EmailAddresses,
		IPAddresses:           csr.IPAddresses,
		URIs:                  csr.URIs,
		KeyUsage:              ku,
		ExtKeyUsage:           eku,
	}

	cert := getCaCertificate()
	key := getPrivateKey()

	certBytes, err := x509.CreateCertificate(rand.Reader, template, &cert, csr.PublicKey, &key)
	if err != nil {
		logger.Error("%v", err)
		return err
	}

	file, err := data.WriteRawIssuedCertificate(certBytes, csr.Subject.CommonName+"_"+hex.EncodeToString(ski[:]))
	if err != nil {
		logger.Error("%v", err)
		return err
	}

	data.Issued(file)

	return nil
}

func createIntermediateCertificate(csr *x509.CertificateRequest) error {

	serialNumberLimit := new(big.Int).Lsh(big.NewInt(1), 128)
	serialNumber, err := rand.Int(rand.Reader, serialNumberLimit)
	if err != nil {
		logger.Error("%v", err)
		return err
	}

	publicKey, err := x509.MarshalPKIXPublicKey(csr.PublicKey)
	if err != nil {
		logger.Error("%v", err)
		return err
	}
	ski := sha256.Sum256(publicKey)
	// todo get baseurl
	cdp, err := url.JoinPath("", url.PathEscape(csr.Subject.CommonName+".crl"))
	if err != nil {
		logger.Error("%v", err)
		return err
	}

	template := &x509.Certificate{
		SerialNumber:          serialNumber,
		Subject:               csr.Subject,
		NotBefore:             time.Now(),
		NotAfter:              time.Now().AddDate(6, 0, 0),
		KeyUsage:              x509.KeyUsageCertSign | x509.KeyUsageCRLSign,
		IsCA:                  true,
		BasicConstraintsValid: true,
		MaxPathLen:            0,
		MaxPathLenZero:        true,
		SubjectKeyId:          ski[:],
		CRLDistributionPoints: []string{cdp},
	}

	cert := getCaCertificate()
	key := getPrivateKey()

	certBytes, err := x509.CreateCertificate(rand.Reader, template, &cert, csr.PublicKey, &key)
	if err != nil {
		logger.Error("%v", err)
		return err
	}

	file, err := data.WriteRawIssuedCertificate(certBytes, csr.Subject.CommonName+"_"+hex.EncodeToString(ski[:]))
	if err != nil {
		logger.Error("%v", err)
		return err
	}

	data.Publish(file, csr.Subject.CommonName+".cer")

	return nil
}
