package ca

import (
	"crypto/ecdsa"
	"crypto/x509"
	"math/big"

	"deleteonerror.com/tyinypki/internal/data"
	"deleteonerror.com/tyinypki/internal/logger"
	"deleteonerror.com/tyinypki/internal/model"
)

type config struct {
	Config      model.Config
	PrivateKey  ecdsa.PrivateKey
	Certificate x509.Certificate
}

var cfg config

func getConfiguration() model.Config {

	if len(cfg.Config.Name) == 0 {
		conf, err := data.ReadCaConfiguration()
		if err != nil {
			logger.Error("Unable to read CA configuration file: %v", err)
		}
		cfg.Config = conf
	}

	return cfg.Config
}

func updateLastSerial(serial *big.Int) error {
	cfg.Config.LastIssuedSerial = serial
	logger.Debug("configuration Changed new LastIssuedSerial %d", serial)
	return data.WriteCaConfiguration(cfg.Config)
}

func updateLastCrl(crl *big.Int) error {
	cfg.Config.LastCRLNumber = crl
	logger.Debug("configuration Changed new LastCRLNumber %d", crl)
	return data.WriteCaConfiguration(cfg.Config)
}

func updateConfiguration(conf model.Config) error {
	logger.Debug("configuration updated")
	cfg.Config = conf
	return data.WriteCaConfiguration(conf)

}
