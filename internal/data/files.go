package data

import (
	"encoding/json"
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

func ReadSetupConfiguration() (model.SetupConfig, error) {

	// move this config file to work
	file, err := os.Open(filepath.Join(RootPath, "config.json"))
	if err != nil {
		return model.SetupConfig{}, err
	}
	defer file.Close()

	var config model.SetupConfig
	decoder := json.NewDecoder(file)
	if err := decoder.Decode(&config); err != nil {
		return model.SetupConfig{}, err
	}

	return config, nil
}

func WriteCertificate(certBytes []byte, filename string) (string, error) {

	filename = filename + ".cer"

	src := getFolderByName("ca-issued")

	certPEM := pem.EncodeToMemory(&pem.Block{
		Type:  "CERTIFICATE",
		Bytes: certBytes,
	})

	dest := filepath.Join(src.path, filename)
	if err := os.WriteFile(dest, certPEM, 0666); err != nil {
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

func WriteKeyNonce(nonce []byte) error {

	src := getFolderByName("ca-key")
	moveOld(*src, "ca.key.nonce")

	file, err := os.OpenFile(
		filepath.Join(src.path, "ca.key.nonce"),
		os.O_WRONLY|os.O_TRUNC|os.O_CREATE,
		0600,
	)
	if err != nil {
		return err
	}
	defer file.Close()

	_, err = file.Write(nonce)
	if err != nil {
		return err
	}
	return nil
}

func ReadKeyNonce() ([]byte, error) {

	src := getFolderByName("ca-key")

	nonce, err := os.ReadFile(filepath.Join(src.path, "ca.key.nonce"))
	if err != nil {
		return nil, err
	}

	return nonce, nil
}

func ReadCaCertificate() ([]byte, error) {
	src := getFolderByName("ca-issued")

	cert, err := os.ReadFile(filepath.Join(src.path, "ca.cer"))
	if err != nil {
		return nil, err
	}

	return cert, nil
}

func ReadKey() ([]byte, error) {

	src := getFolderByName("ca-key")

	encryptedData, err := os.ReadFile(filepath.Join(src.path, "ca.key"))
	if err != nil {
		return nil, err
	}

	return encryptedData, nil
}

func GetLatestCRL() ([]byte, error) {
	src := getFolderByName("ca-crl")

	var maxNum int
	var maxFile fs.DirEntry

	err := filepath.WalkDir(src.path, func(path string, d fs.DirEntry, err error) error {
		if err != nil {
			return err
		}

		if filepath.Ext(d.Name()) == ".crl" {
			numStr := strings.TrimSuffix(d.Name(), ".crl")
			num, err := strconv.Atoi(numStr)
			if err != nil {
				logger.Error("Error converting string to number: %s", err)
				return nil
			}

			if num > maxNum {
				maxNum = num
				maxFile = d
			}
		}

		return nil
	})

	if err != nil {
		return nil, err
	}

	if maxFile != nil {
		file, err := os.Open(maxFile.Name())
		if err != nil {
			return nil, err
		}
		defer file.Close()

		content, err := io.ReadAll(file)
		if err != nil {
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

	file, err := os.OpenFile(
		filepath.Join(src.path, filename),
		os.O_WRONLY|os.O_TRUNC|os.O_CREATE,
		0600,
	)
	if err != nil {
		return "", err
	}
	defer file.Close()

	_, err = file.Write(data)
	if err != nil {
		return "", err
	}
	return filename, nil

}

func GetRevokedCertificates() ([][]byte, error) {
	targetFolder := getFolderByName("ca-revoked")

	var filesData [][]byte

	files, err := os.ReadDir(targetFolder.path)
	if err != nil {
		return nil, err
	}

	for _, file := range files {
		if !file.IsDir() {
			data, err := os.ReadFile(filepath.Join(targetFolder.path, file.Name()))
			if err != nil {
				return nil, err
			}

			filesData = append(filesData, data)
		}
	}

	return filesData, nil
}

type FileData struct {
	Name string
	Data []byte
}

func GetCertificateRequests() ([]FileData, error) {
	targetFolder := getFolderByName("requests")

	var filesData []FileData

	files, err := os.ReadDir(targetFolder.path)
	if err != nil {
		return nil, err
	}

	for _, file := range files {
		if !file.IsDir() {

			data, err := os.ReadFile(filepath.Join(targetFolder.path, file.Name()))
			if err != nil {
				return nil, err
			}

			filesData = append(filesData, FileData{Name: file.Name(), Data: data})
		}
	}

	return filesData, nil
}

func Publish(src string, destName string) error {
	destName = filepath.Clean(destName)

	destFolder := getFolderByName("ca-publish")
	moveOld(*destFolder, destName)

	srcFile, err := os.Open(src)
	if err != nil {
		return err
	}
	defer srcFile.Close()

	dstFile, err := os.Create(filepath.Join(destFolder.path, destName))
	if err != nil {
		return err
	}
	defer dstFile.Close()

	_, err = io.Copy(dstFile, srcFile)
	if err != nil {
		return err
	}

	err = dstFile.Sync()
	if err != nil {
		return err
	}
	return nil
}

func ArchiveRequest(file string) {
	srcFolder := getFolderByName("ca-publish")
	moveOld(*srcFolder, file)
}

func moveOld(f folder, filename string) {
	src := filepath.Join(f.path, filename)
	desFolder := getFolderByName(f.name + "-old")

	_, err := os.Stat(src)
	if err == nil {
		// file exists so we move them
		prefix := time.Now().Format("2006-01-02_15-04-05_")
		targetPath := filepath.Join(desFolder.path, prefix+filename)

		if err := os.Rename(src, targetPath); err != nil {
			logger.Error("Failed to move file %v", err)
		} else {
			logger.Debug("Moved file to %s", targetPath)
		}
	} else if os.IsNotExist(err) {
		return
	} else {
		logger.Error("Unable to move file %s: %v", filename, err)
	}
}
