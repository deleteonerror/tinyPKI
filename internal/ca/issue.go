package ca

import (
	"crypto/rand"
	"crypto/sha256"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/asn1"
	"encoding/hex"
	"encoding/pem"
	"math/big"
	"net/url"
	"time"

	"deleteonerror.com/tyinypki/internal/data"
	"deleteonerror.com/tyinypki/internal/logger"
)

func IssuePendingCaRequests() error {
	requests, err := data.GetCaCertificateRequests()
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
		data.ArchiveRequest(req.Path, req.Name)
	}

	return nil
}

func IssuePendingRequests() error {
	requests := data.GetCertificateRequests()

	if len(requests) == 0 {
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

		switch req.RequestType {
		case "webserver-requests":
			err = createWebServerCertificate(x509Req)
		case "client-requests":
			err = createClientCertificate(x509Req)
		case "code-requests":
			err = createCodeCertificate(x509Req)
		case "server-requests":
			err = createServerCertificate(x509Req)
		case "ocsp-requests":
			err = createOcspCertificate(x509Req)
		case "requests":
			err = createCertificateFromRequest(x509Req)
		default:
			err = createCertificateFromRequest(x509Req)
		}

		if err != nil {
			logger.Error("Failed to Issue request %s: %v", req.Name, err)
			continue
		}
		data.ArchiveRequest(req.Path, req.Name)
	}

	return nil
}

func createCertificateFromRequest(csr *x509.CertificateRequest) error {

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

	cdp, err := url.JoinPath(cfg.Config.BaseUrl, url.PathEscape(cfg.Config.Name+".crl"))
	if err != nil {
		logger.Error("%v", err)
		return err
	}

	aia, err := url.JoinPath(cfg.Config.BaseUrl, url.PathEscape(cfg.Config.Name+".cer"))
	if err != nil {
		logger.Error("%v", err)
		return err
	}
	srl := cfg.Config.LastIssuedSerial

	srl.Add(srl, big.NewInt(1))

	template := &x509.Certificate{
		SerialNumber:          srl,
		Subject:               csr.Subject,
		NotBefore:             time.Now(),
		NotAfter:              time.Now().AddDate(1, 0, 0),
		IsCA:                  false,
		BasicConstraintsValid: false,
		MaxPathLen:            0,
		SubjectKeyId:          ski[:],
		AuthorityKeyId:        cfg.Certificate.SubjectKeyId,
		DNSNames:              csr.DNSNames,
		EmailAddresses:        csr.EmailAddresses,
		IPAddresses:           csr.IPAddresses,
		URIs:                  csr.URIs,
		KeyUsage:              ku,
		ExtKeyUsage:           eku,
		IssuingCertificateURL: []string{aia},
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

	updateLastSerial(srl)
	data.Issued(file)

	return nil
}

func createIntermediateCertificate(csr *x509.CertificateRequest) error {

	publicKey, err := x509.MarshalPKIXPublicKey(csr.PublicKey)
	if err != nil {
		logger.Error("%v", err)
		return err
	}
	ski := sha256.Sum256(publicKey)

	cdp, err := url.JoinPath(cfg.Config.BaseUrl, url.PathEscape(cfg.Config.Name+".crl"))
	if err != nil {
		logger.Error("%v", err)
		return err
	}

	aia, err := url.JoinPath(cfg.Config.BaseUrl, url.PathEscape(cfg.Config.Name+".cer"))
	if err != nil {
		logger.Error("%v", err)
		return err
	}
	srl := cfg.Config.LastIssuedSerial

	logger.Debug("srl is %d\n", srl)
	srl.Add(srl, big.NewInt(1))

	template := &x509.Certificate{
		SerialNumber:          srl,
		Subject:               csr.Subject,
		NotBefore:             time.Now(),
		NotAfter:              time.Now().AddDate(6, 0, 0),
		KeyUsage:              x509.KeyUsageCertSign | x509.KeyUsageCRLSign,
		IsCA:                  true,
		BasicConstraintsValid: true,
		MaxPathLen:            0,
		MaxPathLenZero:        true,
		SubjectKeyId:          ski[:],
		AuthorityKeyId:        cfg.Certificate.SubjectKeyId,
		IssuingCertificateURL: []string{aia},
		CRLDistributionPoints: []string{cdp},
	}

	cert := getCaCertificate()
	key := getPrivateKey()

	certBytes, err := x509.CreateCertificate(rand.Reader, template, &cert, csr.PublicKey, &key)
	if err != nil {
		logger.Error("%v", err)
		return err
	}

	file, err := data.WriteRawIssuedCaCertificate(certBytes, csr.Subject.CommonName+"_"+hex.EncodeToString(ski[:]))
	if err != nil {
		logger.Error("%v", err)
		return err
	}

	updateLastSerial(srl)
	data.Publish(file, csr.Subject.CommonName+".cer")

	return nil
}

func createServerCertificate(csr *x509.CertificateRequest) error {

	keyUsage := x509.KeyUsageDigitalSignature | x509.KeyUsageKeyEncipherment | x509.KeyUsageKeyAgreement

	commentValue, err := asn1.Marshal("Provided by the Tiny PKI Project")
	if err != nil {
		panic(err)
	}

	commentExt := pkix.Extension{
		Id:       asn1.ObjectIdentifier{2, 16, 840, 1, 113730, 1, 13},
		Critical: false,
		Value:    commentValue,
	}

	ext := []pkix.Extension{commentExt}

	eku := []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth, x509.ExtKeyUsageClientAuth}

	return createCertificate(csr, keyUsage, ext, eku)
}

func createWebServerCertificate(csr *x509.CertificateRequest) error {

	keyUsage := x509.KeyUsageDigitalSignature | x509.KeyUsageKeyEncipherment | x509.KeyUsageKeyAgreement

	commentValue, err := asn1.Marshal("Provided by the Tiny PKI Project")
	if err != nil {
		panic(err)
	}

	commentExt := pkix.Extension{
		Id:       asn1.ObjectIdentifier{2, 16, 840, 1, 113730, 1, 13},
		Critical: false,
		Value:    commentValue,
	}

	ext := []pkix.Extension{commentExt}
	eku := []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth}

	return createCertificate(csr, keyUsage, ext, eku)
}

func createClientCertificate(csr *x509.CertificateRequest) error {

	// [ client_reqext ]
	// keyUsage                = critical,digitalSignature,keyEncipherment,dataEncipherment
	// extendedKeyUsage        = emailProtection,clientAuth

	keyUsage := x509.KeyUsageDigitalSignature | x509.KeyUsageKeyEncipherment | x509.KeyUsageDataEncipherment

	commentValue, err := asn1.Marshal("Provided by the Tiny PKI Project")
	if err != nil {
		panic(err)
	}

	commentExt := pkix.Extension{
		Id:       asn1.ObjectIdentifier{2, 16, 840, 1, 113730, 1, 13},
		Critical: false,
		Value:    commentValue,
	}

	ext := []pkix.Extension{commentExt}

	eku := []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth, x509.ExtKeyUsageEmailProtection}

	return createCertificate(csr, keyUsage, ext, eku)
}

func createCodeCertificate(csr *x509.CertificateRequest) error {

	// [ codesign_reqext ]
	// keyUsage                = critical,digitalSignature
	// extendedKeyUsage        = critical,codeSigning

	keyUsage := x509.KeyUsageDigitalSignature

	commentValue, err := asn1.Marshal("Provided by the Tiny PKI Project")
	if err != nil {
		panic(err)
	}

	commentExt := pkix.Extension{
		Id:       asn1.ObjectIdentifier{2, 16, 840, 1, 113730, 1, 13},
		Critical: false,
		Value:    commentValue,
	}

	ext := []pkix.Extension{commentExt}
	eku := []x509.ExtKeyUsage{x509.ExtKeyUsageCodeSigning}

	return createCertificate(csr, keyUsage, ext, eku)
}


func createOcspCertificate(csr *x509.CertificateRequest) error {

	// # Extension for OCSP signing certificates (`man ocsp`).
	// keyUsage                = critical, digitalSignature
	// extendedKeyUsage        = critical, OCSPSigning

	keyUsage := x509.KeyUsageDigitalSignature

	commentValue, err := asn1.Marshal("Provided by the Tiny PKI Project")
	if err != nil {
		panic(err)
	}

	commentExt := pkix.Extension{
		Id:       asn1.ObjectIdentifier{2, 16, 840, 1, 113730, 1, 13},
		Critical: false,
		Value:    commentValue,
	}

	ext := []pkix.Extension{commentExt}

	eku := []x509.ExtKeyUsage{x509.ExtKeyUsageOCSPSigning}

	return createCertificate(csr, keyUsage, ext, eku)
}

func createCertificate(csr *x509.CertificateRequest, ku x509.KeyUsage, extensions []pkix.Extension, eku []x509.ExtKeyUsage) error {

	publicKey, err := x509.MarshalPKIXPublicKey(csr.PublicKey)
	if err != nil {
		logger.Error("%v", err)
		return err
	}
	ski := sha256.Sum256(publicKey)

	cdp, err := url.JoinPath(cfg.Config.BaseUrl, url.PathEscape(cfg.Config.Name+".crl"))
	if err != nil {
		logger.Error("%v", err)
		return err
	}

	aia, err := url.JoinPath(cfg.Config.BaseUrl, url.PathEscape(cfg.Config.Name+".cer"))
	if err != nil {
		logger.Error("%v", err)
		return err
	}
	srl := cfg.Config.LastIssuedSerial

	srl.Add(srl, big.NewInt(1))

	template := &x509.Certificate{
		SerialNumber:          srl,
		Subject:               csr.Subject,
		NotBefore:             time.Now(),
		NotAfter:              time.Now().AddDate(1, 0, 0),
		IsCA:                  false,
		BasicConstraintsValid: false,
		MaxPathLen:            0,
		SubjectKeyId:          ski[:],
		AuthorityKeyId:        cfg.Certificate.SubjectKeyId,
		DNSNames:              csr.DNSNames,
		EmailAddresses:        csr.EmailAddresses,
		IPAddresses:           csr.IPAddresses,
		URIs:                  csr.URIs,
		KeyUsage:              ku,
		ExtKeyUsage:           eku,
		IssuingCertificateURL: []string{aia},
		CRLDistributionPoints: []string{cdp},
		ExtraExtensions:       extensions,
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

	updateLastSerial(srl)
	data.Issued(file)

	return nil
}
