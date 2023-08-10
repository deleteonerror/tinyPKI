package data

import (
	"os"
	"path/filepath"
	"syscall"

	"deleteonerror.com/tyinypki/internal/logger"
)

// getAppPath retrieves the directory path of the currently executing application.
// If it encounters an error while finding the executable, it logs the error and terminates the program with exit code 1.
// Returns: A string containing the directory path of the currently executing application.
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
		{"ca-cer", filepath.Join(StorePath), 0700, "store"},
		{"ca-key", filepath.Join(StorePath, "private"), 0700, "store"},     // The folder for Private Keys
		{"ca-revoked", filepath.Join(StorePath, "revoked"), 0700, "store"}, // The folder for revoked certificates
		{"ca-issued", filepath.Join(StorePath, "issued"), 0700, "store"},   // The folder for issued certificates
		{"ca-crl", filepath.Join(StorePath, "crl"), 0700, "store"},         // The folder for issued certificates
		{"requests", filepath.Join(WorkPath, "reqests"), 0775, "in"},       // The folder for incoming Certificate Requests
		{"issued", filepath.Join(WorkPath, "certificates"), 0775, "out"},   // Out folder for issued certificates including chains
		{"revoke", filepath.Join(WorkPath, "revoke"), 0775, "in"},          // In folder for certificates which should be revoked
		{"ca-publish", filepath.Join(WorkPath, "publish"), 0775, "out"},    // Out folder which contains ca certs and crl's for publishing to aia and cdp
		{"ca-req", filepath.Join(WorkPath, "reqests", "ca"), 0775, "out"},
		{"ca-cert-in", filepath.Join(WorkPath, "certificates", "ca"), 0775, "in"},
		{"webserver-requests", filepath.Join(WorkPath, "reqests", "webserver"), 0775, "in"}, // The folder for incoming Certificate Requests
	}
}

func SetupFolders() {
	for _, f := range folders {
		createAndLogDir(f)
	}
}

// ensureArchiveFolderExists checks if the archive folder (named ".old") exists in the given path.
// If the folder does not exist, it creates the folder and sets the permissions to match the parent directory.
// If there are any issues in retrieving the directory info or creating the folder, an error will be returned.
func ensureArchiveFolderExists(path string) error {
	src, err := os.Stat(path)
	if err != nil {
		logger.Error("Failed to get directory info: %v", err)
		return err
	}

	archive := filepath.Join(path, ".old")
	_, err = os.Stat(archive)
	if err != nil {
		if os.IsNotExist(err) {
			createAndLogDir(folder{perms: src.Mode().Perm(), path: archive})
			return nil
		}
		logger.Error("Failed to get directory info: %v", err)
		return err
	}
	return nil
}

// createAndLogDir creates a new directory specified by the given folder structure 'f'.
// It ensures that the directory is created with the permissions defined in 'f'.
func createAndLogDir(f folder) {
	oldUmask := syscall.Umask(0)
	err := os.MkdirAll(f.path, f.perms)
	if err != nil {
		logger.Error("Failed to create directory %v", err)
	} else {
		logger.Debug("Created %s as %s directory at %s with permissions %v", f.name, f.dirType, f.path, f.perms)
	}
	syscall.Umask(oldUmask)
}

// folder represents a directory structure within the filesystem.
type folder struct {
	// The internal name of the directory "ca-cert-in".
	name string
	// The absolute filesystem path to the directory.
	path string
	// The desired file permissions for the directory, represented as an os.FileMode value.
	perms os.FileMode
	// A description or classification of the directory, used for logging or other descriptive purposes.
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
