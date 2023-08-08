package data

import (
	"os"
	"path/filepath"
	"strings"

	"deleteonerror.com/tyinypki/internal/logger"
)

var StorePath string
var WorkPath string

func Initialize() {

	container, exists := os.LookupEnv("CONTAINER")
	if exists && strings.EqualFold(container, "true") {
		StorePath = "/var/lib/tinyPKI"
		WorkPath = "/var/tinyPKI"
	}

	rootPath, exists := os.LookupEnv("TINY_ROOT_PATH")
	if !exists {
		rootPath = getAppPath()
		WorkPath = filepath.Join(rootPath, "work")
		StorePath = filepath.Join(rootPath, "store")
	} else {
		_, err := os.Stat(rootPath)
		if os.IsNotExist(err) {
			logger.Warning("Environment variable `TINY_ROOT_PATH` set to `%s`, directory not accesible, fallback to default", rootPath)
			rootPath = getAppPath()
		}
		WorkPath = filepath.Join(rootPath, "work")
		StorePath = filepath.Join(rootPath, "store")
	}

	severity, exists := os.LookupEnv("TINY_LOG")
	if !exists {
		logger.LogSeverity = logger.INFO
	} else {
		switch strings.ToLower(severity) {
		case "debug", "dev":
			logger.LogSeverity = logger.DEBUG
		case "warning":
			logger.LogSeverity = logger.WARNING
		case "error":
			logger.LogSeverity = logger.ERROR
		default:
			logger.Warning("Environment variable `TINY_LOG` ignored, Loglevel is default `Info`")
			logger.LogSeverity = logger.INFO
		}
	}
	logger.Info("loglevel is %d", logger.LogSeverity)

	initFolders()
}
