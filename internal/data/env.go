package data

import (
	"os"
	"strings"

	"deleteonerror.com/tyinypki/internal/logger"
)

var RootPath string

func init() {

	rootPath, exists := os.LookupEnv("TINY_ROOT_PATH")

	if !exists {
		RootPath = getAppPath()
	} else {
		_, err := os.Stat(rootPath)
		if os.IsNotExist(err) {
			logger.Warning("Environment variable `TINY_ROOT_PATH` set to `%s`, directory not accesible, fallback to default", rootPath)
			RootPath = getAppPath()
		}
		RootPath = rootPath
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
