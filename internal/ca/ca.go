package ca

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/hex"
	"encoding/pem"
	"math/big"
	"net/url"
	"os"
	"time"

	"deleteonerror.com/tyinypki/internal/data"
	"deleteonerror.com/tyinypki/internal/logger"
	"deleteonerror.com/tyinypki/internal/model"
	"golang.org/x/crypto/chacha20poly1305"
)

var PassPhrase []byte

func VerifyAuthority(pass []byte) {
	PassPhrase = pass

	getPrivateKey()

	cert := getCaCertificate()

	if cert.NotAfter.Before(time.Now().AddDate(0, 0, 90)) {
		logger.Warning("Root cert will expire in less than 90 days.")

	}

	crl, err := getLatestCRL()
	if err != nil {
		logger.Error("Unable not read last CRL: %v", err)
	}
	if crl == nil {
		return
	}

	if crl.NextUpdate.Before(time.Now().AddDate(0, 0, 30)) {
		logger.Warning("CRL will expire in less than 30 days")
	}

}

func SetupAuthority(conf model.SetupConfig, pass []byte) error {
	PassPhrase = pass

	privateKey, err := createPrivateKey(pass)
	if err != nil {
		return err
	}

	publicKey, err := x509.MarshalPKIXPublicKey(&privateKey.PublicKey)
	if err != nil {
		return err
	}
	ski := sha256.Sum256(publicKey)

	cdp, err := url.JoinPath(conf.BaseUrl, url.PathEscape(conf.Name+".crl"))
	if err != nil {
		return err
	}
	aia, err := url.JoinPath(conf.BaseUrl, url.PathEscape(conf.Name+".cer"))
	if err != nil {
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
		return err
	}

	caCert, _ = x509.ParseCertificate(certBytes)

	_, err = data.WriteCertificate(certBytes, caCert.Subject.CommonName+"_"+hex.EncodeToString(caCert.SubjectKeyId))
	if err != nil {
		return err
	}
	// We store the latest CA cert also with the filename ca.cer
	file, err := data.WriteCertificate(certBytes, "ca")
	if err != nil {
		return err
	}
	data.Publish(file, conf.Name+".cer")
	err = PublishRevocationList()
	if err != nil {
		return err
	}

	return nil
}

var pKey ecdsa.PrivateKey

func getPrivateKey() ecdsa.PrivateKey {
	if pKey.D == nil {
		raw, err := getRawPrivateKey(PassPhrase)
		if err != nil {
			logger.Error("Cold not read Private Key file: %v", err)

		}
		key, err := x509.ParseECPrivateKey(raw)
		if err != nil {
			logger.Error("Cold not parse Private Key file: %v", err)
		}
		pKey = *key
		logger.Debug("Private Key loaded.")
	}

	return pKey
}

func getRawPrivateKey(pass []byte) ([]byte, error) {

	encKey := sha256.Sum256([]byte(pass))

	aead, err := chacha20poly1305.NewX(encKey[:])
	if err != nil {
		return nil, err
	}

	nonce, err := data.ReadKeyNonce()
	if err != nil {
		return nil, err
	}

	encryptedKey, err := data.ReadKey()
	if err != nil {
		return nil, err
	}

	x509DerEncoded, err := aead.Open(nil, nonce, encryptedKey, nil)
	if err != nil {
		return nil, err
	}

	return x509DerEncoded, nil
}

func createPrivateKey(pass []byte) (*ecdsa.PrivateKey, error) {
	curve := elliptic.P384()
	ecKey, err := ecdsa.GenerateKey(curve, rand.Reader)
	if err != nil {
		return nil, err
	}

	x509DerEncoded, err := x509.MarshalECPrivateKey(ecKey)
	if err != nil {
		return nil, err
	}

	encKey := sha256.Sum256([]byte(pass))
	aead, err := chacha20poly1305.NewX(encKey[:])
	if err != nil {
		return nil, err
	}

	nonce := make([]byte, aead.NonceSize(), aead.NonceSize()+len(x509DerEncoded)+aead.Overhead())

	_, err = rand.Read(nonce)
	if err != nil {
		return nil, err
	}

	encrypted := aead.Seal(nonce, nonce, x509DerEncoded, nil)
	nonce, ciphertext := encrypted[:aead.NonceSize()], encrypted[aead.NonceSize():]
	data.WriteKey(ciphertext)
	data.WriteKeyNonce(nonce)

	return ecKey, nil
}

var caCert x509.Certificate

func getCaCertificate() x509.Certificate {
	if len(caCert.SubjectKeyId) == 0 {
		derCert, err := data.ReadCaCertificate()
		if err != nil {
			logger.Error("Cold not read Certificate file: %v", err)
			os.Exit(1)
		}
		block, _ := pem.Decode(derCert)

		pCaCert, err := x509.ParseCertificate(block.Bytes)
		if err != nil {
			logger.Error("Cold not pars Certificate file: %v", err)
		}
		logger.Debug("Certificate loaded.")
		caCert = *pCaCert

	}
	return caCert
}
