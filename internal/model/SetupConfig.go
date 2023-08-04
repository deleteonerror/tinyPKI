package model

type SetupConfig struct {
	Name               string `json:"common_name"`
	Country            string `json:"country_iso"`
	Organization       string `json:"organization"`
	OrganizationalUnit string `json:"organizational_unit"`
	BaseUrl            string `json:"base_url"`
}
