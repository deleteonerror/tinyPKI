package ca

import (
	"crypto/rand"
	"crypto/sha256"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/hex"
	"math/big"
	"net/url"
	"os"
	"time"

	"deleteonerror.com/tyinypki/internal/data"
	"deleteonerror.com/tyinypki/internal/logger"
	"deleteonerror.com/tyinypki/internal/model"
)

var PassPhrase []byte

func VerifyAuthority(pass []byte) {
	PassPhrase = pass

	getPrivateKey()

	cert := getCaCertificate()
	if len(cert.Raw) == 0 {
		os.Exit(1)
	}

	if cert.NotAfter.Before(time.Now().AddDate(0, 0, 90)) {
		logger.Warning("Root cert will expire in less than 90 days.")
	} else {
		logger.Info("Root certificate ist valid.")
	}

	crl, err := getLatestCRL()
	if err != nil {
		logger.Error("Unable not read last CRL: %v", err)
	}
	if crl == nil {
		logger.Info("No published crls found.")
		return
	}

	if crl.NextUpdate.Before(time.Now().AddDate(0, 0, 30)) {
		logger.Warning("CRL will expire in less than 30 days")
	} else {
		logger.Info("last published crl ist valid.")
	}
}

func SetupAuthority(conf model.SetupConfig, pass []byte) error {
	PassPhrase = pass

	privateKey, err := createPrivateKey(pass)
	if err != nil {
		logger.Error("%v", err)
		return err
	}

	publicKey, err := x509.MarshalPKIXPublicKey(&privateKey.PublicKey)
	if err != nil {
		logger.Error("%v", err)
		return err
	}
	ski := sha256.Sum256(publicKey)

	cdp, err := url.JoinPath(conf.BaseUrl, url.PathEscape(conf.Name+".crl"))
	if err != nil {
		logger.Error("%v", err)
		return err
	}
	aia, err := url.JoinPath(conf.BaseUrl, url.PathEscape(conf.Name+".cer"))
	if err != nil {
		logger.Error("%v", err)
		return err
	}

	// ToDo: Serial Number is not in rnd
	caCert := &x509.Certificate{
		SerialNumber: big.NewInt(2019),
		Subject: pkix.Name{
			Organization:       []string{conf.Organization},
			OrganizationalUnit: []string{conf.OrganizationalUnit},
			Country:            []string{conf.Country},
			CommonName:         conf.Name,
		},
		Issuer: pkix.Name{
			Organization:       []string{conf.Organization},
			OrganizationalUnit: []string{conf.OrganizationalUnit},
			Country:            []string{conf.Country},
			CommonName:         conf.Name,
		},
		NotBefore:             time.Now(),
		NotAfter:              time.Now().AddDate(10, 0, 0),
		IsCA:                  true,
		KeyUsage:              x509.KeyUsageCertSign | x509.KeyUsageCRLSign,
		BasicConstraintsValid: true,
		AuthorityKeyId:        ski[:],
		SubjectKeyId:          ski[:],
		IssuingCertificateURL: []string{aia},
		CRLDistributionPoints: []string{cdp},
	}

	certBytes, err := x509.CreateCertificate(rand.Reader, caCert, caCert, &privateKey.PublicKey, privateKey) // &key
	if err != nil {
		logger.Error("%v", err)
		return err
	}

	caCert, _ = x509.ParseCertificate(certBytes)

	_, err = data.WriteRawIssuedCertificate(certBytes, caCert.Subject.CommonName+"_"+hex.EncodeToString(caCert.SubjectKeyId))
	if err != nil {
		logger.Error("%v", err)
		return err
	}

	file, err := data.WriteRawCaCertificate(certBytes)
	if err != nil {
		logger.Error("%v", err)
		return err
	}
	data.Publish(file, conf.Name+".cer")
	err = PublishRevocationList()
	if err != nil {
		logger.Error("%v", err)
		return err
	}

	return nil
}
