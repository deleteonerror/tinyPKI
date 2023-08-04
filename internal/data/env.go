package data

import (
	"os"
)

var RootPath string

func init() {

	rootPath, exists := os.LookupEnv("TINY_ROOT_PATH")

	if !exists {
		RootPath = getAppPath()
	} else if rootPath == "" {
		RootPath = getAppPath()
	} else {
	}

	initFolders()
}
