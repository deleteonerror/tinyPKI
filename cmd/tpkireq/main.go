package main

import (
	"flag"
	"fmt"
	"log"

	"deleteonerror.com/tyinypki/internal/ca"
	"deleteonerror.com/tyinypki/internal/data"
	"deleteonerror.com/tyinypki/internal/logger"
	"deleteonerror.com/tyinypki/internal/request"
	"deleteonerror.com/tyinypki/internal/terminal"
)

func init() {
	log.SetFlags(log.LstdFlags)
	log.SetFlags(log.Flags() &^ (log.Lshortfile | log.Llongfile))
}
func main() {
	var filePath string

	verbose := flag.Bool("verbose", false, "enable verbose mode")

	flag.StringVar(&filePath, "r", "", "Give the request to verify.")
	flag.Parse()

	if *verbose {
		logger.LogSeverity = logger.DEBUG
	} else {
		logger.LogSeverity = logger.INFO
	}

	if flag.NArg() > 0 {
		fmt.Println("Positional arguments:")
		for i, arg := range flag.Args() {
			fmt.Printf("Arg %d: %s\n", i, arg)
		}
	}

	flag.Usage = func() {
		fmt.Printf("Usage of %s:\n", "your_program_name")
		flag.PrintDefaults()
	}

	if filePath != "" {
		_, _ = ca.ValidateRequest(filePath)
	} else {
		req := terminal.GetCertificateRequestInteractive()

		keyBytes, key, err := ca.CreatePrivateKey()
		if err != nil {
			fmt.Printf("%v\n", err)
			return
		}

		keyFileName, err := data.WriteRawPrivateKey(keyBytes, req.CommonName)
		if err != nil {
			fmt.Printf("%v\n", err)
			return
		}
		fmt.Printf("Your private key is stored unencrypted at %s\n", keyFileName)
		csrBytes, err := request.CreateSimpleRequest(key, req)
		if err != nil {
			fmt.Printf("%v\n", err)
			return
		}

		csrpath, err := data.WriteRawRequestHere(csrBytes, req.CommonName)
		if err != nil {
			fmt.Printf("%v\n", err)
			return
		}
		fmt.Printf("Your csr is stored at %s\n", csrpath)
	}

}
