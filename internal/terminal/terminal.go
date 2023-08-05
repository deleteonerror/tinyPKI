package terminal

import (
	"fmt"
	"os"
	"syscall"

	"deleteonerror.com/tyinypki/internal/logger"
	"golang.org/x/term"
)

func AskPassphrase() []byte {
	fmt.Print("Enter Password [min 12 characters]: ")
	bytePassword, err := term.ReadPassword(int(syscall.Stdin))
	fmt.Print("\n")
	if err != nil {
		logger.Error("Failed to read pass phrase from terminal: %s", err)
		os.Exit(1)
	}

	// Info: if we init in debug and use it for production, we fail, because we are not able to enter a short passphrase on production
	if len(bytePassword) < 12 && logger.LogSeverity != 0 {
		fmt.Println("You take security serious! Try again ...")
		return AskPassphrase()
	}

	return bytePassword
}
