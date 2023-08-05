package terminal

import (
	"fmt"

	"deleteonerror.com/tyinypki/internal/model"
)

func GetRootConfigInteractive() model.SetupConfig {

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

func GetSubConfigInteractive() model.SetupConfig {

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
