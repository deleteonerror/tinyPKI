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
	data.Initialize(true)
}

func main() {

	// ToDo: run as daemon (only sub ca) and watch files in in/request and in in/revoke
	if data.IsCaConfigured() {
		pass := terminal.AskPassphrase()
		ca.VerifySubAuthority(pass)
	} else {
		config, err := data.ReadSetupConfiguration()
		if err != nil {
			logger.Warning("Configuration not found.")
			config = terminal.GetSubConfigInteractive()
		}
		pass := terminal.AskPassphrase()
		data.SetupFolders()
		err = ca.SetupSubAuthority(config, pass)
		if err != nil {
			logger.Error("Setup failed: %v", err)
			os.Exit(1)
		}
	}
	err := ca.IssuePendingRequests()
	if err != nil {
		logger.Error("Issuance of pending request Failed: %v", err)
	}
}
