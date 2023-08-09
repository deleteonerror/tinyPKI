package ca

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"crypto/x509"
	"os"

	"deleteonerror.com/tyinypki/internal/data"
	"deleteonerror.com/tyinypki/internal/logger"
	"golang.org/x/crypto/chacha20poly1305"
)

func arePublicKeysEqual(key1, key2 *ecdsa.PublicKey) bool {
	if key1 == key2 {
		return true
	}
	if key1 == nil || key2 == nil {
		return false
	}
	return key1.Curve == key2.Curve &&
		key1.X.Cmp(key2.X) == 0 &&
		key1.Y.Cmp(key2.Y) == 0
}

func getPrivateKey() ecdsa.PrivateKey {
	if cfg.PrivateKey.D == nil {
		raw, err := getRawPrivateKey(PassPhrase)
		if err != nil {
			logger.Error("Cold not read Private Key, wrong passphrase or corupted key file.")
			os.Exit(1)
		}
		key, err := x509.ParseECPrivateKey(raw)
		if err != nil {
			logger.Error("Cold not parse Private Key file: %v", err)
			os.Exit(1)
		}
		cfg.PrivateKey = *key
		logger.Debug("Private Key loaded.")
	}

	return cfg.PrivateKey
}

func getRawPrivateKey(pass []byte) ([]byte, error) {

	encKey := sha256.Sum256([]byte(pass))

	aead, err := chacha20poly1305.NewX(encKey[:])
	if err != nil {
		logger.Error("%v", err)
		return nil, err
	}

	nonce, err := data.ReadKeyNonce()
	if err != nil {
		logger.Error("%v", err)
		return nil, err
	}

	encryptedKey, err := data.ReadKey()
	if err != nil {
		logger.Error("%v", err)
		return nil, err
	}

	x509DerEncoded, err := aead.Open(nil, nonce, encryptedKey, nil)
	if err != nil {
		logger.Error("%v", err)
		return nil, err
	}

	return x509DerEncoded, nil
}

func createPrivateKey(pass []byte) (*ecdsa.PrivateKey, error) {
	curve := elliptic.P384()
	ecKey, err := ecdsa.GenerateKey(curve, rand.Reader)
	if err != nil {
		logger.Error("%v", err)
		return nil, err
	}

	x509DerEncoded, err := x509.MarshalECPrivateKey(ecKey)
	if err != nil {
		logger.Error("%v", err)
		return nil, err
	}

	encKey := sha256.Sum256([]byte(pass))
	aead, err := chacha20poly1305.NewX(encKey[:])
	if err != nil {
		logger.Error("%v", err)
		return nil, err
	}

	nonce := make([]byte, aead.NonceSize(), aead.NonceSize()+len(x509DerEncoded)+aead.Overhead())

	_, err = rand.Read(nonce)
	if err != nil {
		logger.Error("%v", err)
		return nil, err
	}

	encrypted := aead.Seal(nonce, nonce, x509DerEncoded, nil)
	nonce, ciphertext := encrypted[:aead.NonceSize()], encrypted[aead.NonceSize():]
	data.WriteKey(ciphertext)
	data.WriteKeyNonce(nonce)

	return ecKey, nil
}
