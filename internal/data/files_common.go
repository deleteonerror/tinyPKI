package data

import (
	"os"
	"path/filepath"
	"strings"
	"time"

	"deleteonerror.com/tyinypki/internal/logger"
	"deleteonerror.com/tyinypki/internal/model"
)

func readFile(path string) ([]byte, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		logger.Error("%v", err)
		return nil, err
	}
	return data, nil
}

func getFilesInFolder(path string) ([]model.FileContentWithPath, error) {
	var filePaths []model.FileContentWithPath

	files, err := os.ReadDir(path)
	if err != nil {
		logger.Error("%v", err)
		return nil, err
	}

	for _, file := range files {
		if !file.IsDir() {
			filePath := filepath.Join(path, file.Name())
			content, err := readFile(filePath)
			if err != nil {
				logger.Error("could not read %s: %v", filePath, err)
				continue
			}
			name := file.Name()
			current := model.NewFileContentWithPath(name, content, path)

			prefixDate, err := getDateFromFilename(name)
			if err != nil {
				logger.Debug("Could not get any date from %s: %v", name, err)
			} else {
				current.PrefixDate = prefixDate
				current.PrefixFromName = true
			}

			filePaths = append(filePaths, *current)
		}
	}

	return filePaths, nil
}

func moveOld(f folder, filename string) {
	src := filepath.Join(f.path, filename)

	err := ensureArchiveFolderExists(f.path)
	if err != nil {
		logger.Error("%v\n", err)
	}

	_, err = os.Stat(src)
	if err == nil {

		prefix := time.Now().UTC().Format("2006-01-02_15-04-05_")
		targetPath := filepath.Join(f.path, ".old", prefix+filename)

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

func getDateFromFilename(fileName string) (time.Time, error) {

	prefixLayout := "2006-01-02_15-04-05_"

	if len(fileName) > len(prefixLayout) {

		prefix := fileName[:len(prefixLayout)-1]

		if strings.HasPrefix(fileName, prefix) {
			parsedTime, err := time.Parse(prefixLayout[:len(prefixLayout)-1], prefix)
			if err != nil {
				logger.Debug("Error parsing time: %v", err)
				return time.Now().UTC(), err
			}
			return parsedTime, nil
		}
	}
	logger.Debug("Could not get Date from FileName: %s", fileName)

	return time.Now().UTC(), nil
}
