package data

import (
	"os"
	"path/filepath"

	"deleteonerror.com/tyinypki/internal/logger"
)

func getAppPath() string {

	exe, err := os.Executable()
	if err != nil {
		logger.Error("Could not get current path: %v", err)
		os.Exit(1)
	}
	exeDir := filepath.Dir(exe)
	return exeDir
}

var folders []folder

func initFolders() {
	folders = []folder{
		{"ca-cer", filepath.Join(RootPath, "store"), 0700, "store"},
		{"ca-cer-old", filepath.Join(RootPath, "store", ".old"), 0700, "store"},
		{"ca-key", filepath.Join(RootPath, "store", "private"), 0700, "store"},              // The folder for Private Keys
		{"ca-key-old", filepath.Join(RootPath, "store", "private", ".old"), 0700, "store"},  // The folder for archived Private Keys
		{"ca-revoked", filepath.Join(RootPath, "store", "revoked"), 0700, "store"},          // The folder for revoked certificates
		{"ca-issued", filepath.Join(RootPath, "store", "issued"), 0700, "store"},            // The folder for issued certificates
		{"ca-crl", filepath.Join(RootPath, "store", "crl"), 0700, "store"},                  // The folder for issued certificates
		{"requests", filepath.Join(RootPath, "work", "reqests"), 0755, "in"},                // The folder for incoming Certificate Requests
		{"requests-old", filepath.Join(RootPath, "work", "reqests", ".old"), 0755, "in"},    // The folder for archived Certificate Requests
		{"issued", filepath.Join(RootPath, "work", "certificates"), 0755, "out"},            // Out folder for issued certificates including chains
		{"revoke", filepath.Join(RootPath, "work", "revoke"), 0755, "in"},                   // In folder for certificates which should be revoked
		{"ca-publish", filepath.Join(RootPath, "work", "publish"), 0755, "out"},             // Out folder which contains ca certs and crl's for publishing to aia and cdp
		{"ca-publish-old", filepath.Join(RootPath, "work", "publish", ".old"), 0755, "out"}, // Out folder which contains archived ca certs and crl's
	}
}

func addRequestOut() {
	reqOut := []folder{
		{"ca-req", filepath.Join(RootPath, "work", "carequest"), 0755, "out"},
		{"cert-in", filepath.Join(RootPath, "work", "cacert"), 0755, "in"},
	}
	folders = append(folders, reqOut...)
}

func SetupFolders() {
	for _, f := range folders {
		createAndLogDir(f)
	}
}

func createAndLogDir(f folder) {
	err := os.MkdirAll(f.path, f.perms)
	if err != nil {
		logger.Error("Failed to create directory %v", err)
	} else {
		logger.Debug("Created %s as %s directory at %s", f.name, f.dirType, f.path)
	}
}

type folder struct {
	name    string
	path    string
	perms   os.FileMode
	dirType string
}

func GetPathByName(name string) string {
	folder := getFolderByName(name)
	return folder.path
}

func getFolderByName(name string) *folder {
	for _, f := range folders {
		if f.name == name {
			return &f
		}
	}
	return nil
}
