package ca

import (
	"crypto/ecdsa"
	"os"
	"time"

	"deleteonerror.com/tyinypki/internal/data"
	"deleteonerror.com/tyinypki/internal/logger"
	"deleteonerror.com/tyinypki/internal/model"
	"deleteonerror.com/tyinypki/internal/request"
)

func SetupSubAuthority(initConfig model.Config, pass []byte) error {
	PassPhrase = pass

	updateConfiguration(initConfig)

	privateKey, err := createEncryptedPrivateKey(pass)
	if err != nil {
		logger.Error("%v", err)
		return err
	}

	rawRequest := request.CreateSubCaRequest(cfg.Config, *privateKey)

	reqFile, err := data.WriteRawRequest(rawRequest, cfg.Config.Name)
	if err != nil {
		logger.Error("%v", err)
		return err
	}

	caIn := data.GetPathByName("ca-cert-in")
	logger.Info("IMPORTANT: Request create at %s. Place the Issued certificate in %s", reqFile, caIn)
	return nil
}

func VerifySubAuthority(pass []byte) {
	PassPhrase = pass

	key := getPrivateKey()
	cert := getCaCertificate()
	getConfiguration()
	data.SetupFolders()
	if len(cert.Raw) == 0 {
		certs, err := data.GetIncommingSubCer()
		if err != nil {
			logger.Warning("No Sub Ca Certificate found.")
			os.Exit(1)
		}
		for _, cer := range certs {
			xCert, err := parseCertificate(cer.Data)
			if err != nil || len(xCert.Raw) == 0 {
				continue
			}
			ecdsaPubKey, ok := xCert.PublicKey.(*ecdsa.PublicKey)
			if !ok {
				continue
			}

			if arePublicKeysEqual(ecdsaPubKey, &key.PublicKey) {
				logger.Debug("matching certificate found > import")

				_, err := data.WritePemCaCertificate(cer.Data)
				if err != nil {
					logger.Error("%v", err)
				}
				cert = xCert

				data.Delete(cer.Path)
				break

			} else {
				logger.Debug("found certificate but public key does not match")
			}
		}
		if len(cert.Raw) == 0 {
			os.Exit(1)
		}
	}

	if cert.NotAfter.Before(time.Now().AddDate(0, 0, 90)) {
		logger.Warning("Sub Ca cert will expire in less than 90 days.")
	} else {
		logger.Info("Sub Ca certificate ist valid.")
	}

	crl, err := getLatestCRL()
	if err != nil {
		logger.Error("Unable not read last CRL: %v", err)
	}
	if crl == nil {
		logger.Info("No published crls found.")
		PublishRevocationList()
		return
	}

	if crl.NextUpdate.Before(time.Now().AddDate(0, 0, 30)) {
		logger.Warning("CRL will expire in less than 30 days")
	} else {
		logger.Info("last published crl ist valid.")
	}

	RevokeCertificates()
}
