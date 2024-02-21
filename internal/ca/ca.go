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
	canf := getConfiguration()
	logger.Debug("%v\n", canf)

	cert := getCaCertificate()
	if len(cert.Raw) == 0 {
		os.Exit(1)
	}

	if cert.NotAfter.Before(time.Now().AddDate(0, 0, 90)) {
		logger.Warning("Root cert will expire in less than 90 days.")
	} else {
		logger.Info("Root certificate ist valid.")
	}

	RevokeCertificates()

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

		err = PublishRevocationList()
		if err != nil {
			logger.Error("%v", err)
		}
	} else {
		logger.Info("last published crl ist valid.")
	}

}

func SetupAuthority(initConfig model.Config, pass []byte) error {
	PassPhrase = pass

	updateConfiguration(initConfig)

	privateKey, err := createEncryptedPrivateKey(pass)
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

	srl := cfg.Config.LastIssuedSerial
	srl.Add(srl, big.NewInt(1))

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

	caCert := &x509.Certificate{
		SerialNumber: srl,
		Subject: pkix.Name{
			Organization:       []string{cfg.Config.Organization},
			OrganizationalUnit: []string{cfg.Config.OrganizationalUnit},
			Country:            []string{cfg.Config.Country},
			CommonName:         cfg.Config.Name,
		},
		Issuer: pkix.Name{
			Organization:       []string{cfg.Config.Organization},
			OrganizationalUnit: []string{cfg.Config.OrganizationalUnit},
			Country:            []string{cfg.Config.Country},
			CommonName:         cfg.Config.Name,
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
	data.Publish(file, cfg.Config.Name+".cer")
	err = PublishRevocationList()
	if err != nil {
		logger.Error("%v", err)
		return err
	}

	updateLastSerial(srl)

	return nil
}
