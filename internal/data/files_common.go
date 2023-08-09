package data

import (
	"os"
	"path/filepath"
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
			current := model.FileContentWithPath{Name: file.Name(), Data: content, Path: filePath}

			filePaths = append(filePaths, current)
		}
	}

	return filePaths, nil
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
