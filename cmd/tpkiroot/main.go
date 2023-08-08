package main

import (
	"log"
	"os"

	"deleteonerror.com/tyinypki/internal/ca"
	"deleteonerror.com/tyinypki/internal/data"
	"deleteonerror.com/tyinypki/internal/logger"
	"deleteonerror.com/tyinypki/internal/terminal"
)

func init() {
	log.SetFlags(log.LstdFlags)
	log.SetFlags(log.Flags() &^ (log.Lshortfile | log.Llongfile))
	data.Initialize()
}

func main() {

	if data.IsCaConfigured() {
		pass := terminal.AskPassphrase()
		ca.VerifyAuthority(pass)
	} else {
		config, err := data.ReadRootSetupConfiguration()
		if err != nil {
			logger.Warning("Configuration not found.")
			config = terminal.GetRootConfigInteractive()
		}
		pass := terminal.AskPassphrase()
		data.SetupFolders()
		err = ca.SetupAuthority(config, pass)
		if err != nil {
			logger.Error("Setup failed: %v", err)
			os.Exit(1)
		}
	}
	err := ca.IssuePendingCaRequests()
	if err != nil {
		logger.Error("Issuance of pending request Failed: %v", err)
	}
}
