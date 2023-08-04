package data

import (
	"os"
	"path/filepath"

	"deleteonerror.com/tyinypki/internal/logger"
)

func IsCaConfigured() bool {

	_, err := os.Stat(filepath.Join(getFolderByName("ca-key").path, "ca.key"))
	if err == nil {
		return true
	} else if os.IsNotExist(err) {
		return false
	} else {
		logger.Warning("Could not read private key file: %v", err)
	}
	return false
}
