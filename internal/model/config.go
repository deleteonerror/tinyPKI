package model

import (
	"encoding/json"
	"math/big"
)

type Config struct {
	Name               string   `json:"common_name"`
	Country            string   `json:"country_iso"`
	Organization       string   `json:"organization"`
	OrganizationalUnit string   `json:"organizational_unit"`
	BaseUrl            string   `json:"base_url"`
	LastIssuedSerial   *big.Int `json:"last_issued_serial"`
	LastCRLNumber      *big.Int `json:"last_crl_number"`
}

type configAlias Config

func (src *Config) UnmarshalJSON(bytes []byte) error {

	tmp := &configAlias{}
	if err := json.Unmarshal(bytes, tmp); err != nil {
		return err
	}

	src.BaseUrl = tmp.BaseUrl
	src.Country = tmp.Country
	src.Name = tmp.Name
	src.Organization = tmp.Organization
	src.OrganizationalUnit = tmp.OrganizationalUnit

	if tmp.LastCRLNumber == nil {
		src.LastCRLNumber = big.NewInt(0)
	} else {
		src.LastCRLNumber = tmp.LastCRLNumber
	}

	if tmp.LastIssuedSerial == nil {
		src.LastIssuedSerial = big.NewInt(0)
	} else {
		src.LastIssuedSerial = tmp.LastIssuedSerial
	}

	return nil
}
