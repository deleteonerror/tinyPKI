package main

import (
	"fmt"
	"log"
	"os"
	"syscall"

	"deleteonerror.com/tyinypki/internal/ca"
	"deleteonerror.com/tyinypki/internal/data"
	"deleteonerror.com/tyinypki/internal/logger"
	"deleteonerror.com/tyinypki/internal/model"
	"golang.org/x/term"
)

func init() {
	log.SetFlags(log.LstdFlags)
	log.SetFlags(log.Flags() &^ (log.Lshortfile | log.Llongfile))
}

func main() {

	// ToDo: run as daemon (only sub ca) and watch files in in/request and in in/revoke
	if data.IsCaConfigured() {
		pass := askPassphrase()
		ca.VerifyAuthority(pass)
	} else {
		config, err := data.ReadSetupConfiguration()
		if err != nil {
			logger.Warning("Configuration not found.")
			config = getConfigInteractive()
		}
		pass := askPassphrase()
		data.SetupFolders()
		err = ca.SetupAuthority(config, pass)
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

func getConfigInteractive() model.SetupConfig {

	config := &model.SetupConfig{}
	fmt.Print("Could not open config file, please enter configuration.")
	fmt.Print("Enter comon name [Tiny pki Root CA]: ")
	fmt.Scan(&config.Name)
	fmt.Print("Enter country ISO code [US]: ")
	fmt.Scan(&config.Country)
	fmt.Print("Enter organization [Delete on error]:")
	fmt.Scan(&config.Organization)
	fmt.Print("Enter organizational unit [code monkeys]: ")
	fmt.Scan(&config.OrganizationalUnit)
	fmt.Print("Enter base url [http://pki.example.com]: ")
	fmt.Scan(&config.BaseUrl)

	return *config
}

func askPassphrase() []byte {
	fmt.Print("Enter Password [min 12 characters]: ")
	bytePassword, err := term.ReadPassword(int(syscall.Stdin))
	fmt.Print("\n")
	if err != nil {
		logger.Error("Failed to read pass phrase from terminal: %s", err)
		os.Exit(1)
	}

	if len(bytePassword) < 12 {
		fmt.Println("You take security serious! Try again ...")
		return askPassphrase()
	}

	return bytePassword
}
