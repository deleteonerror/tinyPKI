package data

import (
	"encoding/pem"
	"io"
	"io/fs"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"time"

	"deleteonerror.com/tyinypki/internal/logger"
	"deleteonerror.com/tyinypki/internal/model"
)

func WriteRawIssuedCertificate(certBytes []byte, filename string) (string, error) {

	folder := getFolderByName("ca-issued")
	path := filepath.Join(folder.path, filename+".cer")

	err := writeRawX509Cert(certBytes, path)
	if err != nil {
		return "", err
	}

	return path, nil
}

func WriteRawIssuedCaCertificate(certBytes []byte, filename string) (string, error) {

	folder := getFolderByName("ca-cert-in")
	path := filepath.Join(folder.path, filename+".cer")

	err := writeRawX509Cert(certBytes, path)
	if err != nil {
		return "", err
	}

	return path, nil
}

func WriteRawCaCertificate(certBytes []byte) (string, error) {

	folder := getFolderByName("ca-cer")
	path := filepath.Join(folder.path, "ca.cer")
	moveOld(*folder, "ca.cer")

	err := writeRawX509Cert(certBytes, path)
	if err != nil {
		return "", err
	}

	return path, nil
}

func WritePemCaCertificate(certBytes []byte) (string, error) {

	folder := getFolderByName("ca-cer")
	path := filepath.Join(folder.path, "ca.cer")
	moveOld(*folder, "ca.cer")

	dest := filepath.Join(path)
	if err := os.WriteFile(dest, certBytes, 0666); err != nil {
		logger.Error("%v", err)
		return "", err
	}
	return path, nil
}

func writeRawX509Cert(x509Bytes []byte, path string) error {

	certPEM := pem.EncodeToMemory(&pem.Block{
		Type:  "CERTIFICATE",
		Bytes: x509Bytes,
	})

	dest := filepath.Join(path)
	if err := os.WriteFile(dest, certPEM, 0666); err != nil {
		logger.Error("%v", err)
		return err
	}
	return nil
}

func WriteRawRequest(csrBytes []byte, filename string) (string, error) {

	csrPEM := pem.EncodeToMemory(&pem.Block{
		Type:  "CERTIFICATE REQUEST",
		Bytes: csrBytes,
	})

	filename = filename + ".csr"
	folder := getFolderByName("ca-req")

	dest := filepath.Join(folder.path, filename)
	if err := os.WriteFile(dest, csrPEM, 0666); err != nil {
		logger.Error("%v", err)
		return "", err
	}
	return dest, nil
}

func WriteRawRequestHere(csrBytes []byte, filename string) (string, error) {

	csrPEM := pem.EncodeToMemory(&pem.Block{
		Type:  "CERTIFICATE REQUEST",
		Bytes: csrBytes,
	})

	filename = filename + ".csr"
	path := getAppPath()

	dest := filepath.Join(path, filename)
	if err := os.WriteFile(dest, csrPEM, 0666); err != nil {
		logger.Error("%v", err)
		return "", err
	}
	return dest, nil
}

func WriteKey(encryptedKey []byte) error {

	src := getFolderByName("ca-key")
	moveOld(*src, "ca.key")

	file, err := os.OpenFile(
		filepath.Join(src.path, "ca.key"),
		os.O_WRONLY|os.O_TRUNC|os.O_CREATE,
		0600,
	)
	if err != nil {
		logger.Error("Failed to write ca file %v", err)

		return err
	}
	defer file.Close()

	bytesWritten, err := file.Write(encryptedKey)
	if err != nil {
		logger.Error("Failed to write ca file %v", err)
		return err
	}
	logger.Info("Wrote %d bytes encrypted key.", bytesWritten)
	return nil
}

func WriteRawPrivateKey(privateKey []byte, filename string) (string, error) {

	pemBlock := pem.EncodeToMemory(&pem.Block{
		Type:  "EC PRIVATE KEY",
		Bytes: privateKey,
	})

	filename = filename + ".key"
	path := getAppPath()

	dest := filepath.Join(path, filename)
	if err := os.WriteFile(dest, pemBlock, 0600); err != nil {
		logger.Error("%v", err)
		return "", err
	}
	return dest, nil
}

func WriteKeyNonce(nonce []byte) error {

	src := getFolderByName("ca-key")
	moveOld(*src, "ca.key.nonce")

	file, err := os.OpenFile(
		filepath.Join(src.path, "ca.key.nonce"),
		os.O_WRONLY|os.O_TRUNC|os.O_CREATE,
		0600,
	)
	if err != nil {
		logger.Error("%v", err)
		return err
	}
	defer file.Close()

	_, err = file.Write(nonce)
	if err != nil {
		logger.Error("%v", err)
		return err
	}
	return nil
}

func ReadKeyNonce() ([]byte, error) {

	src := getFolderByName("ca-key")
	path := filepath.Join(src.path, "ca.key.nonce")

	return readFile(path)
}

func ReadKey() ([]byte, error) {

	src := getFolderByName("ca-key")
	path := filepath.Join(src.path, "ca.key")

	return readFile(path)
}

func GetLatestCRL() ([]byte, error) {
	src := getFolderByName("ca-crl")

	var maxNum int
	var maxFile string

	err := filepath.WalkDir(src.path,
		func(path string, d fs.DirEntry, err error) error {
			if err != nil {
				logger.Error("%v", err)
				return err
			}

			if filepath.Ext(d.Name()) == ".crl" {
				numStr := strings.TrimSuffix(d.Name(), ".crl")
				num, err := strconv.Atoi(numStr)
				if err != nil {
					logger.Error("Error converting string to number: %s", err)
					return nil
				}

				if num >= maxNum {
					maxNum = num
					maxFile = path
				}
			}
			return nil
		})

	if err != nil {
		logger.Error("%v", err)
		return nil, err
	}

	if maxFile != "" {
		file, err := os.Open(maxFile)
		if err != nil {
			logger.Error("%v", err)
			return nil, err
		}
		defer file.Close()

		content, err := io.ReadAll(file)
		if err != nil {
			logger.Error("%v", err)
			return nil, err
		}

		return content, nil
	}
	return nil, nil
}

func WriteCRL(data []byte, id string) (string, error) {

	filename := id + ".crl"
	src := getFolderByName("ca-crl")
	moveOld(*src, filename)

	path := filepath.Join(src.path, filename)

	file, err := os.OpenFile(
		path,
		os.O_WRONLY|os.O_TRUNC|os.O_CREATE,
		0600,
	)
	if err != nil {
		logger.Error("%v", err)
		return "", err
	}
	defer file.Close()

	_, err = file.Write(data)
	if err != nil {
		logger.Error("%v", err)
		return "", err
	}
	return path, nil
}

func GetRevokedCertificatesFromCaStore() ([]model.FileContentWithPath, error) {
	src := getFolderByName("ca-revoked")

	files, err := getFilesInFolder(src.path)
	if err != nil {
		logger.Error("%v", err)
		return nil, err
	}
	if len(files) == 0 {
		logger.Debug("No Revoked certificates found")
		return nil, nil
	}
	return files, nil
}

func GetNewRevokations() ([]model.FileContentWithPath, error) {
	src := getFolderByName("revoke")

	files, err := getFilesInFolder(src.path)
	if err != nil {
		logger.Error("%v", err)
		return nil, err
	}
	if len(files) == 0 {
		logger.Debug("No Revoked certificates found")
		return nil, nil
	}
	return files, nil
}

func ImportRevokedCertificate(in model.FileContentWithPath) error {

	src := in.Path
	destDir := getFolderByName("ca-revoked")

	_, err := os.Stat(src)
	if err == nil {
		prefix := time.Now().UTC().Format("2006-01-02_15-04-05_")
		targetPath := filepath.Join(destDir.path, prefix+in.Name)

		if err := os.Rename(src, targetPath); err != nil {
			logger.Error("Failed to move file %v", err)
		} else {
			logger.Debug("Moved file to %s", targetPath)
		}
	} else if os.IsNotExist(err) {
		return err
	} else {
		logger.Error("Unable to move file %s: %v", in.Name, err)
		return err
	}
	return nil

}

func ReadCaCertificate() ([]byte, error) {
	src := getFolderByName("ca-cer")
	path := filepath.Join(src.path, "ca.cer")

	return readFile(path)
}

func GetIncommingSubCer() ([]model.FileContentWithPath, error) {
	src := getFolderByName("ca-cert-in")
	files, err := getFilesInFolder(src.path)
	if err != nil {
		logger.Error("%v", err)
		return nil, err
	}
	if len(files) == 0 {
		logger.Debug("No new Sub ca certificate found to import")
		return nil, nil
	}
	return files, nil
}

func GetX509CertificateRequest(path string) ([]byte, error) {
	raw, err := readFile(path)
	if err != nil {
		return nil, err
	}

	block, _ := pem.Decode(raw)
	return block.Bytes, nil

}

func GetCaCertificateRequests() ([]model.FileContentWithPath, error) {
	src := getFolderByName("ca-req")

	files, err := getFilesInFolder(src.path)
	if err != nil {
		logger.Error("%v", err)
		return nil, err
	}
	if len(files) == 0 {
		logger.Debug("No new ca certificate requests found to issue")
		return nil, nil
	}
	return files, nil
}

func GetCertificateRequests() ([]model.FileContentWithPath, error) {
	src := getFolderByName("requests")

	files, err := getFilesInFolder(src.path)
	if err != nil {
		logger.Error("%v", err)
		return nil, err
	}
	if len(files) == 0 {
		logger.Debug("No new certificate requests found to issue")
		return nil, nil
	}
	return files, nil
}

func Publish(src string, destName string) error {
	destName = filepath.Clean(destName)

	destFolder := getFolderByName("ca-publish")
	moveOld(*destFolder, destName)

	srcFile, err := os.Open(src)
	if err != nil {
		logger.Error("%v", err)
		return err
	}
	defer srcFile.Close()

	dstFile, err := os.Create(filepath.Join(destFolder.path, destName))
	if err != nil {
		logger.Error("%v", err)
		return err
	}
	defer dstFile.Close()

	_, err = io.Copy(dstFile, srcFile)
	if err != nil {
		logger.Error("%v", err)
		return err
	}

	err = dstFile.Sync()
	if err != nil {
		logger.Error("%v", err)
		return err
	}
	return nil
}

func Issued(src string) error {
	destFolder := getFolderByName("issued")
	fileName := filepath.Base(src)

	moveOld(*destFolder, fileName)

	srcFile, err := os.Open(src)
	if err != nil {
		logger.Error("%v", err)
		return err
	}
	defer srcFile.Close()

	dstFile, err := os.Create(filepath.Join(destFolder.path, fileName))
	if err != nil {
		logger.Error("%v", err)
		return err
	}
	defer dstFile.Close()

	_, err = io.Copy(dstFile, srcFile)
	if err != nil {
		logger.Error("%v", err)
		return err
	}

	err = dstFile.Sync()
	if err != nil {
		logger.Error("%v", err)
		return err
	}
	return nil
}

func ArchiveRequest(path, file string) {
	srcFolder := folder{path: path, name: file}
	logger.Debug("Archiving request %s", file)
	moveOld(srcFolder, file)
}

func Delete(path string) error {
	err := os.Remove(path)
	if err != nil {
		logger.Error("%v", err)
	}
	return nil
}
