package data

import (
	"encoding/json"
	"os"
	"path/filepath"

	"deleteonerror.com/tyinypki/internal/logger"
	"deleteonerror.com/tyinypki/internal/model"
)

func ReadSetupConfiguration(root bool) (model.Config, error) {
	configFileName := "sub.config.json"

	if root {
		configFileName = "root.config.json"
	}

	p := filepath.Join(WorkPath, configFileName)
	logger.Debug("%s\n", p)
	file, err := os.Open(p)
	if err != nil {
		logger.Error("%v\n", err)
		return model.Config{}, err
	}
	defer file.Close()

	var config model.Config
	decoder := json.NewDecoder(file)
	if err := decoder.Decode(&config); err != nil {
		logger.Error("%v\n", err)
		return model.Config{}, err
	}

	return config, nil
}

func ReadCaConfiguration() (model.Config, error) {
	src := getFolderByName("ca-cer")
	path := filepath.Join(filepath.Join(src.path, "config.json"))

	content, err := readFile(path)
	if err != nil {
		return model.Config{}, err
	}

	var config model.Config
	if err := json.Unmarshal(content, &config); err != nil {
		return model.Config{}, err
	}

	return config, nil
}

func WriteCaConfiguration(config model.Config) error {
	src := getFolderByName("ca-cer")

	file, err := os.OpenFile(
		filepath.Join(src.path, "config.json"), os.O_WRONLY|os.O_TRUNC|os.O_CREATE, 0600)
	if err != nil {
		logger.Error("%v", err)
		return err
	}
	defer file.Close()

	encoder := json.NewEncoder(file)
	err = encoder.Encode(config)
	if err != nil {
		logger.Error("%v", err)
		return err
	}
	return nil
}

// file, err := os.OpenFile(
// 	filepath.Join(src.path, "ca.key.nonce"),
// 	os.O_WRONLY|os.O_TRUNC|os.O_CREATE,
// 	0600,
// )
// if err != nil {
// 	logger.Error("%v", err)
// 	return err
// }
// defer file.Close()
