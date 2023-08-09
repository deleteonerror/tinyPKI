package terminal

import (
	"fmt"
	"math/big"

	"deleteonerror.com/tyinypki/internal/model"
)

func GetRootConfigInteractive() model.Config {

	config := &model.Config{}
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

	config.LastIssuedSerial = big.NewInt(0)

	return *config
}

func GetSubConfigInteractive() model.Config {

	config := &model.Config{}
	fmt.Print("Could not open config file, please enter configuration.")
	fmt.Print("Enter comon name [Tiny pki Sub CA]: ")
	fmt.Scan(&config.Name)
	fmt.Print("Enter country ISO code [US]: ")
	fmt.Scan(&config.Country)
	fmt.Print("Enter organization [Delete on error]:")
	fmt.Scan(&config.Organization)
	fmt.Print("Enter organizational unit [code monkeys]: ")
	fmt.Scan(&config.OrganizationalUnit)
	fmt.Print("Enter base url [http://pki.example.com]: ")
	fmt.Scan(&config.BaseUrl)

	config.LastIssuedSerial = big.NewInt(0)

	return *config
}
