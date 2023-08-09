package ca

import (
	"bytes"
	"time"

	"deleteonerror.com/tyinypki/internal/data"
	"deleteonerror.com/tyinypki/internal/logger"
	"deleteonerror.com/tyinypki/internal/model"
)

func RevokeCertificates() {

	rawCerts, err := data.GetNewRevokations()
	if err != nil {
		logger.Error("%v", err)
	}

	count, err := importRevocations(rawCerts)
	if err != nil {
		logger.Error("%v", err)
	}
	if count > 0 {
		err = PublishRevocationList()
		if err != nil {
			logger.Error("%v", err)
		}
	}
}

func importRevocations(certificates []model.FileContentWithPath) (int, error) {
	ca := getCaCertificate()
	count := 0

	for _, cert := range certificates {
		certData, err := parseCertificate(cert.Data)
		if err != nil || len(certData.Raw) == 0 || certData.NotAfter.Before(time.Now()) {
			continue
		}

		if !bytes.Equal(ca.SubjectKeyId, certData.AuthorityKeyId) {
			continue
		}

		err = data.ImportRevokedCertificate(cert)
		if err != nil {
			continue
		}
		count++
	}

	return count, nil
}
